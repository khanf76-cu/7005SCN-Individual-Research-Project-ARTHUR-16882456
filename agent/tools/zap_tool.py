"""Scoped OWASP ZAP wrapper: broad active DAST coverage.

ZAP is a Java application, not apt-packaged; setup.sh downloads a pinned
"Linux" release tarball from GitHub (best-effort, same as nuclei/
osv-scanner -- see those modules' docstrings for why that's non-fatal if
it fails) and needs a JRE (`apt install default-jre`, also in setup.sh).

Unlike every other tool here, ZAP isn't a single subprocess call: it's a
long-lived daemon driven over its own local REST API. This module:
  1. launches `zap.sh -daemon` bound to 127.0.0.1 with a random per-run
     API key (never exposed outside this process/host),
  2. polls until the API responds,
  3. runs a spider crawl (passive link discovery) to populate ZAP's site
     tree, then an active scan (ZAP actually attacking discovered
     endpoints -- the slow, high-value part),
  4. pulls the alerts ZAP found for the target,
  5. always shuts the daemon down in a `finally` block, including on any
     exception, timeout, or Ctrl-C-equivalent, so a failed run never
     leaves an orphaned Java process using RAM on the box.

A target to actively scan must still be reachable, in scope, and this
whole flow can take several minutes on a non-trivial site -- the
`max_scan_time_s` budget below applies to spider+active-scan combined, and
a cutoff mid-scan still returns whatever alerts ZAP had already found
(reported as `truncated=True`), the same truncation pattern used for
nikto/nmap's own time limits.
"""
from __future__ import annotations

import secrets
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation

STARTUP_TIMEOUT_S = 90
POLL_INTERVAL_S = 2
SHUTDOWN_GRACE_S = 10

_RISK_MAP = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}


@dataclass
class ZapAlert:
    name: str
    risk: str
    confidence: str
    url: str
    param: str | None
    description: str
    solution: str
    cwe_id: str | None = None


@dataclass
class ZapResult:
    target: str
    alerts: list[ZapAlert] = field(default_factory=list)
    duration_s: float = 0.0
    truncated: bool = False
    error: str | None = None


def zap_available() -> bool:
    return shutil.which("zap.sh") is not None


def _api_get(base_url: str, api_key: str, endpoint: str, **params) -> dict:
    resp = requests.get(
        f"{base_url}{endpoint}",
        params={**params, "apikey": api_key},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def _wait_for_daemon(base_url: str, api_key: str, deadline: float) -> bool:
    while time.time() < deadline:
        try:
            _api_get(base_url, api_key, "/JSON/core/view/version/")
            return True
        except requests.RequestException:
            time.sleep(POLL_INTERVAL_S)
    return False


def _poll_until_complete(base_url: str, api_key: str, status_endpoint: str, scan_id: str, deadline: float) -> bool:
    """Returns True if the scan reached 100%, False if the deadline hit first."""
    while time.time() < deadline:
        try:
            status = _api_get(base_url, api_key, status_endpoint, scanId=scan_id)
            if int(status.get("status", "0")) >= 100:
                return True
        except (requests.RequestException, ValueError):
            pass
        time.sleep(POLL_INTERVAL_S)
    return False


def run_zap(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    max_scan_time_s: int = 300,
) -> ZapResult:
    if not config.is_in_scope(config.target_origin):
        raise ScopeViolation(f"Target {config.target_origin!r} is not in allowed scope")
    if not zap_available():
        raise RuntimeError(
            "zap.sh is not on PATH. setup.sh downloads OWASP ZAP from GitHub releases; "
            "if that step failed, install it manually from https://www.zaproxy.org/download/ "
            "(needs a JRE: `apt install default-jre`)."
        )

    started = time.time()
    port = 8098  # fixed, localhost-only; ARTHUR runs one scan at a time so no port-collision handling needed
    api_key = secrets.token_hex(16)
    base_url = f"http://127.0.0.1:{port}"

    evidence.log("TOOL_CALL", tool="zap", target=config.target_origin, port=port)

    alerts: list[ZapAlert] = []
    truncated = False
    error: str | None = None
    proc: subprocess.Popen | None = None

    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "zap_daemon.log"
        try:
            with log_path.open("w") as log_file:
                proc = subprocess.Popen(
                    [
                        "zap.sh",
                        "-daemon",
                        "-host",
                        "127.0.0.1",
                        "-port",
                        str(port),
                        "-config",
                        f"api.key={api_key}",
                        "-config",
                        "api.disablekey=false",
                    ],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )

            if not _wait_for_daemon(base_url, api_key, time.time() + STARTUP_TIMEOUT_S):
                error = "ZAP daemon did not become ready within the startup timeout"
            else:
                overall_deadline = time.time() + max_scan_time_s

                # ZAP's active scanner refuses to scan a URL that isn't
                # already a node in its internal Sites tree, and the spider
                # alone doesn't guarantee that: against a CDN-fronted or
                # otherwise unusual target it can legitimately crawl zero
                # pages (robots.txt, odd redirects, a WAF treating ZAP's
                # crawler differently from a browser), in which case
                # `ascan/action/scan` fails with HTTP 400 even though the
                # target itself is perfectly reachable. accessUrl forces
                # ZAP's own HTTP client to fetch the root URL once, which
                # seeds the Sites tree regardless of what the spider finds.
                try:
                    _api_get(
                        base_url, api_key, "/JSON/core/action/accessUrl/",
                        url=config.target_origin, followRedirects="true",
                    )
                except requests.RequestException as exc:
                    error = f"ZAP couldn't access the target to seed its site tree: {exc}"

                if error is None:
                    try:
                        spider_resp = _api_get(base_url, api_key, "/JSON/spider/action/scan/", url=config.target_origin)
                        spider_id = spider_resp.get("scan")
                        if spider_id is not None and not _poll_until_complete(
                            base_url, api_key, "/JSON/spider/view/status/", spider_id, overall_deadline
                        ):
                            truncated = True
                    except requests.RequestException as exc:
                        # Non-fatal: accessUrl above already seeded the root
                        # URL, so an active scan against just that one page
                        # is still possible even without a crawl.
                        truncated = True
                        evidence.log("TOOL_WARN", tool="zap", phase="spider", error=str(exc))

                    if time.time() < overall_deadline:
                        try:
                            ascan_resp = _api_get(base_url, api_key, "/JSON/ascan/action/scan/", url=config.target_origin)
                            ascan_id = ascan_resp.get("scan")
                            if ascan_id is not None and not _poll_until_complete(
                                base_url, api_key, "/JSON/ascan/view/status/", ascan_id, overall_deadline
                            ):
                                truncated = True
                        except requests.RequestException as exc:
                            # Still worth reporting whatever the passive
                            # scanner already picked up from accessUrl/spider
                            # rather than discarding the whole run over this.
                            truncated = True
                            evidence.log("TOOL_WARN", tool="zap", phase="ascan", error=str(exc))
                    else:
                        truncated = True

                    alerts_resp = _api_get(base_url, api_key, "/JSON/core/view/alerts/", baseurl=config.target_origin)
                    for a in alerts_resp.get("alerts", []):
                        risk = _RISK_MAP.get((a.get("risk") or "").lower(), "info")
                        alerts.append(
                            ZapAlert(
                                name=a.get("alert", ""),
                                risk=risk,
                                confidence=a.get("confidence", ""),
                                url=a.get("url", config.target_origin),
                                param=a.get("param") or None,
                                description=a.get("description", "") or "",
                                solution=a.get("solution", "") or "",
                                cwe_id=str(a.get("cweid")) if a.get("cweid") not in (None, "-1") else None,
                            )
                        )
        except requests.RequestException as exc:
            error = f"ZAP API request failed: {exc}"
        finally:
            if proc is not None:
                try:
                    _api_get(base_url, api_key, "/JSON/core/action/shutdown/")
                except requests.RequestException:
                    pass
                try:
                    proc.wait(timeout=SHUTDOWN_GRACE_S)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=SHUTDOWN_GRACE_S)

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="zap",
        alert_count=len(alerts),
        duration_s=duration,
        truncated=truncated,
        error=error,
    )

    return ZapResult(
        target=config.target_origin,
        alerts=alerts,
        duration_s=duration,
        truncated=truncated,
        error=error,
    )
