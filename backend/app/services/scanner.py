from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import SessionLocal
from ..models import Asset, Finding, Scan, Service, Severity
from .risk import calculate_risk

PROFILE_PORTS = {
    "basic_discovery": [22, 80, 443],
    "common_services": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080],
    "web_security": [80, 443, 8000, 8080, 8443],
    "tls_configuration": [443, 465, 636, 993, 995, 8443],
    "full_authorized": [21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443],
}

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
}


async def _connect(address: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> tuple[int, str] | None:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=timeout)
            banner = ""
            if port not in {80, 443, 8443}:
                try:
                    banner = (await asyncio.wait_for(reader.read(256), timeout=0.25)).decode("utf-8", "replace").strip()
                except (TimeoutError, UnicodeError):
                    pass
            writer.close()
            await writer.wait_closed()
            return port, banner[:256]
        except (OSError, TimeoutError):
            return None


def _upsert_asset(db: Session, project_id: str, address: str) -> Asset:
    asset = db.query(Asset).filter(Asset.project_id == project_id, Asset.ip_address == address).first()
    if not asset:
        try:
            hostname = socket.gethostbyaddr(address)[0]
        except (socket.herror, socket.gaierror):
            hostname = None
        asset = Asset(project_id=project_id, ip_address=address, hostname=hostname)
        db.add(asset)
        db.flush()
    asset.last_seen = datetime.now(timezone.utc)
    asset.status = "active"
    return asset


def _finding_for_service(db: Session, scan: Scan, asset: Asset, port: int, service_name: str) -> Finding | None:
    risky = {
        21: (Severity.medium, "Cleartext FTP service exposed", "Replace FTP with SFTP and restrict access."),
        23: (Severity.high, "Cleartext Telnet service exposed", "Disable Telnet and use SSH with strong authentication."),
        445: (Severity.medium, "SMB service exposed", "Restrict SMB to required hosts and enforce modern SMB signing."),
        3389: (Severity.high, "Remote desktop service exposed", "Place RDP behind a VPN, require MFA and restrict source addresses."),
        5900: (Severity.high, "VNC service exposed", "Disable direct VNC exposure or place it behind an authenticated tunnel."),
        6379: (Severity.critical, "Redis service exposed", "Bind Redis to trusted interfaces and require authenticated, encrypted access."),
    }
    if port not in risky:
        return None
    severity, title, remediation = risky[port]
    risk = calculate_risk(severity.value, 88, asset.criticality, exposure=4)
    return Finding(
        project_id=scan.project_id, asset_id=asset.id, scan_id=scan.id, title=title,
        description=f"A TCP connect check found {service_name} listening on port {port}. Validate exposure and configuration manually.",
        port=port, service=service_name, severity=severity, confidence=88,
        evidence=f"TCP connection completed to {asset.ip_address}:{port}; no exploitation was attempted.",
        remediation=remediation, references=["https://www.cisa.gov/resources-tools/resources/cybersecurity-performance-goals"],
        risk_score=risk.score,
    )


async def execute_scan(scan_id: str, addresses: list[str], custom_ports: list[int], timeout: float, demo: bool) -> None:
    settings = get_settings()
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 3
        db.commit()
        try:
            if demo:
                await _execute_demo(db, scan)
                return
            ports = custom_ports or PROFILE_PORTS.get(scan.profile, PROFILE_PORTS["common_services"])
            ports = sorted(set(ports))[: settings.max_ports]
            semaphore = asyncio.Semaphore(settings.scan_concurrency)
            total = max(1, len(addresses) * len(ports))
            completed = 0
            for address in addresses:
                scan = db.get(Scan, scan_id)
                if not scan or scan.status == "cancelled":
                    return
                results = await asyncio.gather(*[_connect(address, port, timeout, semaphore) for port in ports])
                open_results = [result for result in results if result]
                completed += len(ports)
                if open_results:
                    asset = _upsert_asset(db, scan.project_id, address)
                    scan.hosts_found += 1
                    for port, banner in open_results:
                        service_name = SERVICE_NAMES.get(port, "unknown")
                        service = db.query(Service).filter(Service.asset_id == asset.id, Service.port == port, Service.protocol == "tcp").first()
                        if not service:
                            service = Service(asset_id=asset.id, port=port, name=service_name, banner=banner or None, tls=port in {443, 465, 636, 993, 995, 8443})
                            db.add(service)
                        finding = _finding_for_service(db, scan, asset, port, service_name)
                        if finding:
                            db.add(finding)
                            scan.findings_found += 1
                    scan.services_found += len(open_results)
                scan.progress = min(95, 5 + int(completed / total * 90))
                db.commit()
            scan.status = "completed"
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        except Exception as exc:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error = f"Scan stopped safely: {type(exc).__name__}"
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()


async def _execute_demo(db: Session, scan: Scan) -> None:
    demo_assets = [
        ("10.20.0.12", "lab-web-01", "Ubuntu Linux", [(22, "ssh"), (80, "http"), (443, "https")]),
        ("10.20.0.24", "lab-db-01", "Linux appliance", [(22, "ssh"), (5432, "postgresql")]),
        ("10.20.0.42", "training-iot", "Embedded Linux", [(23, "telnet"), (80, "http")]),
    ]
    for index, (address, hostname, os_name, services) in enumerate(demo_assets, 1):
        scan = db.get(Scan, scan.id)
        if scan.status == "cancelled":
            return
        asset = _upsert_asset(db, scan.project_id, address)
        asset.hostname, asset.probable_os = hostname, os_name
        for port, name in services:
            existing = db.query(Service).filter(Service.asset_id == asset.id, Service.port == port).first()
            if not existing:
                db.add(Service(asset_id=asset.id, port=port, name=name, product="Simulated service", version="training", tls=port == 443))
            finding = _finding_for_service(db, scan, asset, port, name)
            if finding:
                db.add(finding)
                scan.findings_found += 1
        scan.hosts_found += 1
        scan.services_found += len(services)
        scan.progress = 10 + index * 28
        db.commit()
        await asyncio.sleep(0.2)
    asset = db.query(Asset).filter(Asset.project_id == scan.project_id, Asset.ip_address == "10.20.0.12").first()
    if asset:
        risk = calculate_risk("medium", 92, asset.criticality, exposure=3)
        db.add(Finding(
            project_id=scan.project_id, asset_id=asset.id, scan_id=scan.id,
            title="HTTP response missing Content-Security-Policy", description="The simulated web response did not include a Content-Security-Policy header.",
            port=443, service="https", severity=Severity.medium, confidence=92,
            evidence="Simulated HEAD response; payload content was not retained.", remediation="Define and test a restrictive Content-Security-Policy header.",
            references=["https://owasp.org/www-project-secure-headers/"], risk_score=risk.score,
        ))
        scan.findings_found += 1
    scan.status = "completed"
    scan.progress = 100
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()

