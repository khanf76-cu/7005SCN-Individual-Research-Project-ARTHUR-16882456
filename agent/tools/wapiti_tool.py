"""Scoped wapiti wrapper: broad black-box DAST coverage.

wapiti3 (pip-installable: `pip install wapiti3`) is a pure-Python,
daemon-free web vulnerability scanner that crawls the target itself and
tests discovered pages/parameters for a wide module list (XSS, SQL
injection, SSRF, XXE, open redirect, CSRF, CRLF injection, exposed
backups, command execution, and more). It complements nikto (which is
mostly a signature/known-file scanner, not an active input-fuzzer) and
sqlmap (SQL-injection-only) with genuine dynamic testing across several
OWASP categories in one pass.

`--scope domain` keeps wapiti's own crawler inside the target's
hostname -- the same boundary RunConfig.allowed_hosts enforces for every
other tool here, since wapiti crawls and requests pages itself rather
than going through scoped_request().

Only the `vulnerabilities` section of wapiti's JSON report is parsed into
findings; its `anomalies`/`additionals` sections are lower-confidence
signals (timeouts, generic info) that would add noise without much
VA-relevant value at this scope.

ssrf/xxe are enabled in DEFAULT_MODULES below -- see the comment there
for what that trades away (an external OOB callback service sees a
response from the target to confirm a blind hit).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation

# Not wapiti's full default module list (it also probes things
# nikto/security_headers_tool already cover, e.g. some header/cookie
# checks) -- scoped to the modules that do genuine dynamic input-testing
# nothing else in ARTHUR does.
#
# ssrf/xxe are included here at the user's explicit request. Both rely on
# an external third-party out-of-band callback service (wapiti3.ovh) to
# confirm a blind interaction: a target response that proves the
# injection worked gets relayed to that service rather than staying
# between ARTHUR and the authorized target. That is a real side channel
# outside the two-party scan relationship the rest of this tool keeps to
# -- accepted here as a deliberate tradeoff for SSRF/XXE coverage, not an
# oversight. If that tradeoff stops being acceptable, drop "ssrf,xxe"
# from this list to go back to the fully self-contained module set.
DEFAULT_MODULES = "backup,crlf,csrf,exec,htaccess,redirect,ssrf,sql,xss,xxe"


@dataclass
class WapitiFinding:
    category: str  # wapiti's vulnerability-class name, e.g. "SQL Injection"
    method: str
    path: str
    parameter: str | None
    module: str
    info: str
    http_request: str


@dataclass
class WapitiResult:
    target: str
    findings: list[WapitiFinding] = field(default_factory=list)
    duration_s: float = 0.0
    truncated: bool = False
    error: str | None = None


def wapiti_available() -> bool:
    return shutil.which("wapiti") is not None


def _parse_report(report_path: Path) -> list[WapitiFinding]:
    findings: list[WapitiFinding] = []
    data = json.loads(report_path.read_text())
    for category, items in (data.get("vulnerabilities") or {}).items():
        for item in items or []:
            findings.append(
                WapitiFinding(
                    category=category,
                    method=item.get("method", "GET"),
                    path=item.get("path", ""),
                    parameter=item.get("parameter") or None,
                    module=item.get("module", ""),
                    info=item.get("info", ""),
                    http_request=item.get("http_request", ""),
                )
            )
    return findings


def run_wapiti(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    modules: str = DEFAULT_MODULES,
    level: int = 1,
    max_scan_time_s: int = 240,
    extra_start_urls: list[str] | None = None,
) -> WapitiResult:
    """`extra_start_urls` seeds wapiti's crawler with URLs recon_agent
    already discovered (e.g. dirbrute hits, sitemap entries), in addition
    to the target root -- without this, wapiti only tests what it can
    find by crawling from "/", which misses any page nothing links to."""
    if not config.is_in_scope(config.target_origin):
        raise ScopeViolation(f"Target {config.target_origin!r} is not in allowed scope")
    if not wapiti_available():
        raise RuntimeError(
            "wapiti is not on PATH. Install it (e.g. `pip install wapiti3`) before running this tool."
        )

    started = time.time()

    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "wapiti_report.json"
        cmd = [
            "wapiti",
            "-u",
            config.target_origin,
            "--scope",
            "domain",
            "-m",
            modules,
            "-l",
            str(level),
            "-f",
            "json",
            "-o",
            str(report_path),
            "--no-bugreport",
            "--flush-session",  # ARTHUR runs one-shot scans; never resume/skip a prior session's "already attacked" URLs
            "--max-scan-time",
            str(max_scan_time_s),
        ]
        for extra_url in (extra_start_urls or []):
            if config.is_in_scope(extra_url):
                cmd += ["-s", extra_url]

        evidence.log("TOOL_CALL", tool="wapiti", command=cmd, target=config.target_origin)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_scan_time_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            evidence.log("TOOL_ERROR", tool="wapiti", error="timeout")
            return WapitiResult(
                target=config.target_origin,
                findings=[],
                duration_s=time.time() - started,
                truncated=True,
                error="wapiti timed out",
            )

        findings: list[WapitiFinding] = []
        error: str | None = None
        if report_path.exists():
            try:
                findings = _parse_report(report_path)
            except (json.JSONDecodeError, OSError) as exc:
                error = f"failed to parse wapiti JSON report: {exc}"
        elif proc.returncode != 0:
            stderr_tail = (proc.stderr or "").strip()[-300:]
            error = f"wapiti exited with returncode {proc.returncode}: {stderr_tail}"

        duration = time.time() - started
        evidence.log(
            "TOOL_RESULT",
            tool="wapiti",
            returncode=proc.returncode,
            finding_count=len(findings),
            duration_s=duration,
            error=error,
        )

        return WapitiResult(
            target=config.target_origin,
            findings=findings,
            duration_s=duration,
            truncated=False,
            error=error,
        )
