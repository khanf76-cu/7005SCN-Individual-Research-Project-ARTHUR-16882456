"""TLS/certificate hygiene check (OWASP A04 - Cryptographic Failures).

Pure Python via `ssl`/`socket` plus the `cryptography` package for
certificate parsing -- no subprocess, no new system binary, nothing for
setup.sh to install beyond a normal pip package. Checks the three things
that matter most at VA-agent scope: negotiated protocol version (flags
SSLv3/TLSv1.0/TLSv1.1 as deprecated), certificate expiry, and whether the
certificate is self-signed or otherwise fails default trust validation.

Response-header checks (HSTS etc.) are already covered by
security_headers_tool.py, so this module stays purely at the
TLS/certificate transport layer to avoid duplicate findings between the
two tools.
"""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARNING_DAYS = 14


@dataclass
class TlsIssue:
    kind: str  # weak_protocol | expired_cert | expiring_soon | self_signed | untrusted | hostname_mismatch
    detail: str


@dataclass
class TlsResult:
    target_host: str
    target_port: int
    applicable: bool  # False for a plain-http target -- not a failure, just n/a
    negotiated_protocol: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_after: str | None = None
    issues: list[TlsIssue] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None


def _cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def run_tls_check(config: RunConfig, evidence: EvidenceLogger, *, timeout_s: int = 10) -> TlsResult:
    parsed = urlparse(config.target_origin)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if host not in config.allowed_hosts:
        raise ScopeViolation(f"Host {host!r} is not in allowed scope for the TLS check")

    evidence.log("TOOL_CALL", tool="tls", target=f"{host}:{port}", scheme=parsed.scheme)
    started = time.time()

    if parsed.scheme != "https":
        result = TlsResult(target_host=host, target_port=port, applicable=False, duration_s=time.time() - started)
        evidence.log("TOOL_RESULT", tool="tls", applicable=False, duration_s=result.duration_s)
        return result

    issues: list[TlsIssue] = []
    negotiated_protocol: str | None = None
    cert_subject = cert_issuer = cert_not_after = None
    error: str | None = None

    try:
        # Pass 1: default (verifying) context, purely to see *why* trust
        # fails, if it does -- self-signed vs. untrusted CA vs. hostname
        # mismatch each need a different message.
        try:
            verify_ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout_s) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated_protocol = ssock.version()
        except ssl.SSLCertVerificationError as exc:
            reason = getattr(exc, "verify_message", "") or str(exc)
            reason_lower = reason.lower()
            if "self signed" in reason_lower or "self-signed" in reason_lower:
                issues.append(TlsIssue("self_signed", reason))
            elif "hostname mismatch" in reason_lower or "doesn't match" in reason_lower:
                issues.append(TlsIssue("hostname_mismatch", reason))
            else:
                issues.append(TlsIssue("untrusted", reason))
        except (ssl.SSLError, OSError):
            pass  # handled by the unverified pass below; this pass is diagnostic only

        # Pass 2: non-verifying context, so we can always read the
        # negotiated protocol and the certificate itself even when trust
        # validation failed above.
        noverify_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        noverify_ctx.check_hostname = False
        noverify_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with noverify_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated_protocol = negotiated_protocol or ssock.version()
                der_cert = ssock.getpeercert(binary_form=True)

        if der_cert:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            cert_subject = _cn(cert.subject) or cert.subject.rfc4514_string()
            cert_issuer = _cn(cert.issuer) or cert.issuer.rfc4514_string()
            not_after = cert.not_valid_after_utc
            cert_not_after = not_after.isoformat()

            now = datetime.now(timezone.utc)
            if not_after < now:
                issues.append(TlsIssue("expired_cert", f"Certificate expired on {cert_not_after}"))
            elif (not_after - now).days <= EXPIRY_WARNING_DAYS:
                days_left = (not_after - now).days
                issues.append(
                    TlsIssue("expiring_soon", f"Certificate expires in {days_left} day(s), on {cert_not_after}")
                )

            if cert.subject == cert.issuer and not any(i.kind == "self_signed" for i in issues):
                issues.append(TlsIssue("self_signed", f"Certificate is self-signed (subject == issuer: {cert_subject})"))

        if negotiated_protocol and negotiated_protocol in WEAK_PROTOCOLS:
            issues.append(TlsIssue("weak_protocol", f"Server negotiated deprecated protocol {negotiated_protocol}"))

    except (OSError, ssl.SSLError) as exc:
        error = f"TLS connection failed: {exc}"

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="tls",
        applicable=True,
        issue_count=len(issues),
        negotiated_protocol=negotiated_protocol,
        duration_s=duration,
        error=error,
    )

    return TlsResult(
        target_host=host,
        target_port=port,
        applicable=True,
        negotiated_protocol=negotiated_protocol,
        cert_subject=cert_subject,
        cert_issuer=cert_issuer,
        cert_not_after=cert_not_after,
        issues=issues,
        duration_s=duration,
        error=error,
    )
