"""Session-cookie attribute check (partial OWASP A07 - Authentication
Failures coverage).

A full A07 pass needs test accounts and login-flow knowledge ARTHUR
doesn't have (see the VA-scope discussion this was built from). What *is*
cheaply and reliably checkable without any of that is whether cookies the
target sets carry the `Secure`, `HttpOnly`, and `SameSite` attributes --
missing any of them is a real, independently-reportable weakness
(session-cookie theft over plain HTTP, cookie access via XSS, and CSRF
exposure respectively), regardless of what the cookie is used for.

Uses `requests` directly rather than the shared `scoped_request()`
wrapper because `HttpResult.headers` collapses a response's multiple
`Set-Cookie` headers into a single dict (lossy for this purpose); the
scope check below is the same one `scoped_request()` applies.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation


@dataclass
class CookieIssue:
    cookie_name: str
    missing_attribute: str  # "Secure" | "HttpOnly" | "SameSite"
    detail: str


@dataclass
class CookieResult:
    checked_url: str
    cookies_found: int = 0
    issues: list[CookieIssue] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None


# A single connect/read failure here is retried once after a short pause
# before giving up -- ARTHUR runs 8 VA sub-tools (plus recon, plus nmap)
# concurrently against the same target, and a small/locally-hosted target
# (a lightweight Docker container, say) can genuinely be too saturated to
# accept a new connection for a moment under that load without actually
# being down. A target that's really unreachable still fails cleanly
# after the retry, same as before.
_RETRY_ATTEMPTS = 2
_RETRY_DELAY_S = 3.0


def run_cookie_check(config: RunConfig, evidence: EvidenceLogger, *, path: str = "/") -> CookieResult:
    url = config.target_origin + ("" if path.startswith("/") else "/") + path
    if not config.is_in_scope(url):
        raise ScopeViolation(f"URL {url!r} is outside authorized scope")

    evidence.log("TOOL_CALL", tool="cookies", url=url)
    started = time.time()
    issues: list[CookieIssue] = []
    cookies_found = 0
    error: str | None = None
    is_https = url.lower().startswith("https://")

    try:
        resp = None
        for attempt in range(1, _RETRY_ATTEMPTS + 1):
            try:
                resp = requests.get(url, timeout=config.request_timeout_s, allow_redirects=False)
                break
            except requests.RequestException:
                if attempt >= _RETRY_ATTEMPTS:
                    raise
                evidence.log("TOOL_RETRY", tool="cookies", url=url, attempt=attempt)
                time.sleep(_RETRY_DELAY_S)
        cookies_found = len(resp.cookies)
        for c in resp.cookies:
            if is_https and not c.secure:
                issues.append(
                    CookieIssue(c.name, "Secure", f"Cookie '{c.name}' is set over HTTPS without the Secure attribute")
                )
            if not c.has_nonstandard_attr("HttpOnly"):
                issues.append(
                    CookieIssue(
                        c.name,
                        "HttpOnly",
                        f"Cookie '{c.name}' lacks HttpOnly, so it is readable by JavaScript (incl. via XSS)",
                    )
                )
            samesite = c.get_nonstandard_attr("SameSite")
            if not samesite:
                issues.append(
                    CookieIssue(c.name, "SameSite", f"Cookie '{c.name}' has no SameSite attribute (CSRF exposure)")
                )
    except requests.RequestException as exc:
        error = str(exc)

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="cookies",
        cookies_found=cookies_found,
        issue_count=len(issues),
        duration_s=duration,
        error=error,
    )

    return CookieResult(
        checked_url=url,
        cookies_found=cookies_found,
        issues=issues,
        duration_s=duration,
        error=error,
    )
