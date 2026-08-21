from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from ..config import get_settings

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class UnsafeTarget(ValueError):
    pass


@dataclass
class ValidatedTarget:
    original: str
    normalized: str
    addresses: list[str]
    kind: str


def _permitted(address: ipaddress._BaseAddress) -> bool:
    if not isinstance(address, ipaddress.IPv4Address):
        return False
    return address.is_private and not address.is_link_local and not address.is_multicast and not address.is_unspecified


def validate_target(target: str, max_hosts: int | None = None) -> ValidatedTarget:
    settings = get_settings()
    limit = max_hosts or settings.max_cidr_hosts
    clean = target.strip().rstrip(".")
    if not clean or any(char in clean for char in " ;|&$`\\\n\r\t"):
        raise UnsafeTarget("Malformed target")
    try:
        network = ipaddress.ip_network(clean, strict=False)
        if network.num_addresses > limit:
            raise UnsafeTarget(f"Target contains {network.num_addresses} addresses; maximum is {limit}")
        addresses = [address for address in network.hosts()] if network.num_addresses > 2 else list(network)
        if not addresses or any(not _permitted(address) for address in addresses):
            raise UnsafeTarget("Only private IPv4 or localhost targets are allowed")
        return ValidatedTarget(clean, str(network) if "/" in clean else str(addresses[0]), [str(a) for a in addresses], "cidr" if "/" in clean else "ip")
    except ValueError as ip_error:
        if "/" in clean or not HOSTNAME_RE.fullmatch(clean):
            raise UnsafeTarget(str(ip_error)) from ip_error
    try:
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(clean, None, family=socket.AF_INET)})
    except socket.gaierror as exc:
        raise UnsafeTarget("Hostname could not be resolved") from exc
    if not resolved or len(resolved) > limit:
        raise UnsafeTarget("Hostname resolution exceeds the safe host limit")
    parsed = [ipaddress.ip_address(address) for address in resolved]
    if any(not _permitted(address) for address in parsed):
        raise UnsafeTarget("Hostname resolves outside permitted private ranges")
    return ValidatedTarget(clean, clean.lower(), resolved, "hostname")


def parse_scope(scope: str) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for raw in scope.split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks


def within_scope(addresses: list[str], scope: str) -> bool:
    scopes = parse_scope(scope)
    return bool(scopes) and all(any(ipaddress.ip_address(address) in network for network in scopes) for address in addresses)

