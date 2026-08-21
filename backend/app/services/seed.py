from datetime import date, datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..models import (
    Alert, Assessment, AssessmentResponse, AssessmentTemplate, Asset, DetectionRule, Finding,
    Project, RemediationTask, Role, Scan, Severity, Service, TrafficRecord, User,
)
from ..security import hash_password
from .risk import assessment_scores, calculate_risk

CONTROLS = [
    ("AM-01", "Asset management", "Maintain an accurate inventory of devices and services."),
    ("AC-01", "Access control", "Apply least privilege and review access regularly."),
    ("AU-01", "Authentication", "Use multi-factor authentication for privileged access."),
    ("NS-01", "Network security", "Segment critical systems and restrict management interfaces."),
    ("DP-01", "Data protection", "Encrypt sensitive data in transit and at rest."),
    ("LM-01", "Logging and monitoring", "Centralize and review security-relevant logs."),
    ("VM-01", "Vulnerability management", "Prioritize and remediate known vulnerabilities."),
    ("IR-01", "Incident response", "Document and exercise the incident response plan."),
    ("BR-01", "Backup and recovery", "Test protected backups and recovery procedures."),
    ("SD-01", "Secure software development", "Use code review and dependency scanning."),
    ("CS-01", "Cloud security", "Review cloud configurations against a secure baseline."),
    ("PS-01", "Physical security", "Control physical access to infrastructure."),
    ("SA-01", "Security awareness", "Provide recurring role-based security awareness."),
    ("TP-01", "Third-party risk", "Assess vendors before onboarding and periodically thereafter."),
]


def seed_database(db: Session) -> None:
    if db.query(User).first():
        return
    users = [
        User(email="admin@netsecure.local", full_name="Avery Admin", organization="NetSecure Lab", role=Role.administrator, password_hash=hash_password("AdminDemo!2026")),
        User(email="researcher@netsecure.local", full_name="Riley Researcher", organization="NetSecure Lab", role=Role.researcher, password_hash=hash_password("ResearchDemo!2026")),
        User(email="student@netsecure.local", full_name="Sam Student", organization="Cybersecurity 201", role=Role.student, password_hash=hash_password("StudentDemo!2026")),
        User(email="student2@netsecure.local", full_name="Jordan Student", organization="Cybersecurity 201", role=Role.student, password_hash=hash_password("StudentDemo!2026")),
    ]
    db.add_all(users)
    db.flush()
    researcher = users[1]
    projects = [
        Project(name="Campus Lab Baseline", description="Authorized training VLAN baseline and remediation exercise.", scope="10.20.0.0/24", owner_id=researcher.id, start_date=date.today() - timedelta(days=30), end_date=date.today() + timedelta(days=60)),
        Project(name="Web Systems Study", description="Longitudinal study of simulated web-service hardening.", scope="192.168.56.0/24", owner_id=researcher.id, start_date=date.today() - timedelta(days=90)),
    ]
    db.add_all(projects)
    db.flush()
    project = projects[0]
    assets = [
        Asset(project_id=project.id, ip_address="10.20.0.12", hostname="lab-web-01", probable_os="Ubuntu Linux", criticality=4, risk_score=68),
        Asset(project_id=project.id, ip_address="10.20.0.24", hostname="lab-db-01", probable_os="Linux appliance", criticality=5, risk_score=42),
        Asset(project_id=project.id, ip_address="10.20.0.42", hostname="training-iot", probable_os="Embedded Linux", criticality=2, risk_score=76),
        Asset(project_id=project.id, ip_address="10.20.0.51", hostname="student-ws-04", probable_os="Windows 11", criticality=2, risk_score=18),
    ]
    db.add_all(assets)
    db.flush()
    services = [(assets[0], 22, "ssh"), (assets[0], 80, "http"), (assets[0], 443, "https"), (assets[1], 5432, "postgresql"), (assets[2], 23, "telnet"), (assets[2], 80, "http"), (assets[3], 445, "smb")]
    for asset, port, name in services:
        db.add(Service(asset_id=asset.id, port=port, name=name, product="Simulated service", version="training", tls=port == 443))
    scan = Scan(project_id=project.id, user_id=researcher.id, authorization_id="seed-authorization", name="Weekly safe baseline", target="10.20.0.0/27", profile="common_services", ports="22,80,443,5432", status="completed", progress=100, hosts_found=4, services_found=7, findings_found=4, started_at=datetime.now(timezone.utc)-timedelta(hours=4), completed_at=datetime.now(timezone.utc)-timedelta(hours=3, minutes=57))
    # Keep the seed FK portable when SQLite foreign keys are enabled by inserting a matching auth record later in init.
    from ..models import AuthorizationRecord
    auth = AuthorizationRecord(id="seed-authorization", project_id=project.id, user_id=researcher.id, target=scan.target, purpose="Authorized simulated baseline", approved_scope=project.scope, policy_accepted=True)
    db.add(auth)
    db.add(scan)
    db.flush()
    finding_specs = [
        (assets[2], "Cleartext Telnet service exposed", Severity.high, 84, "Disable Telnet and use SSH."),
        (assets[0], "HTTP response missing Content-Security-Policy", Severity.medium, 55, "Deploy and test a restrictive CSP."),
        (assets[1], "Database listener accessible across lab segment", Severity.medium, 47, "Restrict the database security group to application hosts."),
        (assets[3], "Legacy SMB signing policy", Severity.low, 24, "Require SMB signing through the managed baseline."),
    ]
    findings = []
    for asset, title, severity, score, remediation in finding_specs:
        finding = Finding(project_id=project.id, asset_id=asset.id, scan_id=scan.id, title=title, description="Simulated observation for defensive training. Validate before remediation.", severity=severity, confidence=88, evidence="Generated sample metadata; no exploitation performed.", remediation=remediation, references=[], risk_score=score)
        findings.append(finding)
        db.add(finding)
    db.flush()
    for finding in findings[:3]:
        db.add(RemediationTask(project_id=project.id, finding_id=finding.id, title=finding.remediation, priority=finding.severity.value, status="open", due_date=date.today()+timedelta(days=14)))
    protocols = [("TCP", 13240, 11_420_000), ("TLS", 7820, 8_640_000), ("DNS", 4240, 680_000), ("HTTP", 2860, 3_100_000), ("UDP", 1980, 420_000)]
    for index, (protocol, packets, byte_count) in enumerate(protocols):
        db.add(TrafficRecord(project_id=project.id, source=f"10.20.0.{12+index}", destination="10.20.0.1" if protocol == "DNS" else "10.20.0.24", source_port=49152+index, destination_port={"DNS":53,"HTTP":80,"TLS":443}.get(protocol, 443), protocol=protocol, packets=packets, bytes=byte_count, metadata_json={"demo": True}, observed_at=datetime.now(timezone.utc)-timedelta(minutes=index*7)))
    rules = [
        DetectionRule(name="Cleartext protocol observed", description="Flags common cleartext application protocols.", severity=Severity.medium, rule_type="port_match", conditions={"ports":[21,23,80,110,143]}, built_in=True),
        DetectionRule(name="Connection burst", description="Flags unusually dense connection metadata.", severity=Severity.high, rule_type="connection_count", conditions={"threshold":100,"window_seconds":60}, built_in=True),
    ]
    db.add_all(rules)
    db.flush()
    db.add_all([
        Alert(project_id=project.id, rule_id=rules[0].id, rule_name=rules[0].name, description="Telnet metadata observed on the training IoT device.", severity=Severity.high, source="10.20.0.42", destination="10.20.0.51", evidence="18 TCP connections to destination port 23 in 5 minutes.", investigation="Confirm the device owner and replace Telnet with SSH.", status="new"),
        Alert(project_id=project.id, rule_id=rules[1].id, rule_name="New service observed", description="A service appeared since the previous baseline.", severity=Severity.medium, source="10.20.0.12", destination="10.20.0.12", evidence="TCP/8080 was absent from the previous simulated baseline.", investigation="Verify the change ticket and service owner.", status="investigating"),
    ])
    template = AssessmentTemplate(name="Foundational security posture", description="An educational baseline spanning fourteen security-control categories.", framework="General controls (informed by NIST CSF and CIS Controls)", controls=[{"id": cid,"category":cat,"prompt":prompt} for cid,cat,prompt in CONTROLS])
    db.add(template)
    db.flush()
    complete = Assessment(project_id=project.id, template_id=template.id, user_id=researcher.id, name="Q2 Security Posture Review", status="completed", score=0)
    incomplete = Assessment(project_id=project.id, template_id=template.id, user_id=users[2].id, name="Student lab self-assessment", status="in_progress", score=0)
    db.add_all([complete, incomplete])
    db.flush()
    response_values = ["implemented","partially_implemented","implemented","partially_implemented","implemented","partially_implemented","not_implemented","partially_implemented","implemented","not_reviewed","not_applicable","implemented","partially_implemented","not_implemented"]
    for (cid, category, _), value in zip(CONTROLS, response_values):
        db.add(AssessmentResponse(assessment_id=complete.id, control_id=cid, category=category, response=value, notes="Simulated evidence reviewed." if value == "implemented" else "Follow-up evidence needed."))
    scores = assessment_scores(response_values)
    complete.score, complete.maturity_score, complete.residual_risk = scores["score"], scores["maturity_score"], scores["residual_risk"]
    db.commit()

