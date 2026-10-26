"""Security response-header audit.

Fetches the target's root page once (through the same scoped_request
primitive every other HTTP-based tool uses) and checks for the small
set of response headers that are considered baseline web-security
hygiene. This is pure recon/triage information -- a missing header is
not itself a vulnerability, so every finding is "info" severity; it's
useful context for a human reader of the report, not something the
correlate agent needs to re-adjudicate.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .http_tool import scoped_request

# header name -> short human-readable description of what it's for,
# used when building the finding text.
SECURITY_HEADERS = {
    "strict-transport-security": "enforces HTTPS on future visits (HSTS)",
    "x-content-type-options": "stops the browser guessing/sniffing a response's MIME type",
    "x-frame-options": "mitigates clickjacking by controlling framing",
    "content-security-policy": "restricts which sources scripts/styles/etc. may load from",
    "referrer-policy": "controls how much of the URL is leaked to other sites via the Referer header",
}


@dataclass
class SecurityHeadersResult:
    checked_url: str
    present: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def run_security_headers_check(config: RunConfig, evidence: EvidenceLogger) -> SecurityHeadersResult:
    started = time.time()
    evidence.log("TOOL_CALL", tool="security_headers", target=config.target_origin)

    res = scoped_request(config, evidence, method="GET", path="/")
    lower_headers = {k.lower() for k in (res.headers or {}).keys()}

    present = [h for h in SECURITY_HEADERS if h in lower_headers]
    missing = [h for h in SECURITY_HEADERS if h not in lower_headers]

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="security_headers",
        present_count=len(present),
        missing_count=len(missing),
        duration_s=duration,
    )

    return SecurityHeadersResult(
        checked_url=res.url,
        present=present,
        missing=missing,
        duration_s=duration,
    )
