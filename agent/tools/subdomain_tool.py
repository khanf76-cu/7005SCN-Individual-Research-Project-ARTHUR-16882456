"""DNS-based subdomain enumeration.

Pure DNS A-record lookups against a small wordlist -- no network traffic
to the target itself, no third-party enumeration API. This only makes
sense when the target is a real domain name; if it's a literal IP (as
your Juice Shop target is), subdomain enumeration is skipped and logged
as not-applicable rather than silently doing nothing.

Deliberately does NOT treat a resolved subdomain as in-scope for further
testing by the other tools -- it's recon information for the report, not
an automatic scope expansion. Testing a discovered subdomain requires a
separate, explicit authorization and a new RunConfig.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from ..config import RunConfig
from ..evidence import EvidenceLogger

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "common_subdomains.txt"


@dataclass
class SubdomainHit:
    subdomain: str
    resolved_ip: str


@dataclass
class SubdomainResult:
    base_domain: str | None
    applicable: bool
    skip_reason: str | None
    hits: list[SubdomainHit] = field(default_factory=list)
    duration_s: float = 0.0


def _is_literal_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def run_subdomain_enum(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    wordlist_path: Path = DEFAULT_WORDLIST,
    timeout_s: float = 2.0,
) -> SubdomainResult:
    hostname = urlparse(config.target_origin).hostname or ""

    if _is_literal_ip(hostname):
        evidence.log("TOOL_SKIPPED", tool="subdomain_enum", reason="target is a literal IP, not a domain")
        return SubdomainResult(
            base_domain=None,
            applicable=False,
            skip_reason=f"target host {hostname!r} is a literal IP address; "
            "subdomain enumeration does not apply",
        )

    evidence.log("TOOL_CALL", tool="subdomain_enum", base_domain=hostname)
    started = time.time()
    socket.setdefaulttimeout(timeout_s)

    words = [
        w.strip()
        for w in wordlist_path.read_text(encoding="utf-8").splitlines()
        if w.strip() and not w.startswith("#")
    ]

    hits: list[SubdomainHit] = []
    for word in words:
        candidate = f"{word}.{hostname}"
        try:
            resolved = socket.gethostbyname(candidate)
            hits.append(SubdomainHit(subdomain=candidate, resolved_ip=resolved))
        except OSError:
            continue

    duration = time.time() - started
    evidence.log("TOOL_RESULT", tool="subdomain_enum", hit_count=len(hits), duration_s=duration)

    return SubdomainResult(
        base_domain=hostname,
        applicable=True,
        skip_reason=None,
        hits=hits,
        duration_s=duration,
    )
