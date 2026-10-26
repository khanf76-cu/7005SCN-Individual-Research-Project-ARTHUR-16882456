"""Opportunistic dependency-vulnerability check via OSV-Scanner (OWASP
A03 - Software Supply Chain Failures, best-effort black-box adaptation).

OSV-Scanner (github.com/google/osv-scanner) is fundamentally a
source-code/SBOM tool: it reads a dependency manifest (package.json,
requirements.txt, composer.lock, etc.) and checks each pinned version
against the OSV vulnerability database. ARTHUR doesn't have the target's
source tree -- it's a black-box external scanner -- so this module
adapts the idea rather than using the tool as intended: it probes the
target for common dependency-manifest filenames at the site root (the
same kind of accidentally-exposed file recon_agent's path checks already
catch, e.g. /.env or /.git/config), and only if one is actually exposed
does it download that file and run osv-scanner against it.

This will come back empty on most production sites -- exposing a
lockfile at the web root is already a misconfiguration most sites don't
have. When it *does* find something, it's high-signal: a real,
version-confirmed, known CVE in a dependency the target is actually
running, not a guess.

Like nikto/nmap, osv-scanner isn't apt-packaged; setup.sh downloads a
pinned release binary from GitHub, best-effort. If that step failed,
`osv_scanner_available()` reports it absent and this check is skipped
cleanly rather than failing the whole VA pass.
"""
from __future__ import annotations

import json
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

# filename -> ecosystem label (purely descriptive; osv-scanner identifies
# the ecosystem itself from the filename once it's on disk).
CANDIDATE_MANIFESTS = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "Gemfile.lock",
    "go.sum",
    "Cargo.lock",
)


@dataclass
class OsvVulnerability:
    manifest_file: str
    package_name: str
    package_version: str
    ecosystem: str
    vuln_id: str
    summary: str
    severity: str | None = None


@dataclass
class OsvResult:
    target: str
    manifests_checked: int = 0
    manifests_found: list[str] = field(default_factory=list)
    vulnerabilities: list[OsvVulnerability] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None


def osv_scanner_available() -> bool:
    return shutil.which("osv-scanner") is not None


def _parse_osv_json(data: dict, manifest_name: str) -> list[OsvVulnerability]:
    out: list[OsvVulnerability] = []
    for result in data.get("results") or []:
        for pkg in result.get("packages") or []:
            pkg_info = pkg.get("package") or {}
            for vuln in pkg.get("vulnerabilities") or []:
                severity = None
                db_specific = vuln.get("database_specific") or {}
                if isinstance(db_specific, dict):
                    severity = db_specific.get("severity")
                out.append(
                    OsvVulnerability(
                        manifest_file=manifest_name,
                        package_name=pkg_info.get("name", ""),
                        package_version=pkg_info.get("version", ""),
                        ecosystem=pkg_info.get("ecosystem", ""),
                        vuln_id=vuln.get("id", ""),
                        summary=vuln.get("summary", "") or "",
                        severity=severity,
                    )
                )
    return out


def run_osv_check(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    manifests: tuple[str, ...] = CANDIDATE_MANIFESTS,
    max_scan_time_s: int = 60,
) -> OsvResult:
    if not config.is_in_scope(config.target_origin):
        raise ScopeViolation(f"Target {config.target_origin!r} is not in allowed scope")
    if not osv_scanner_available():
        raise RuntimeError(
            "osv-scanner is not on PATH. setup.sh downloads it from GitHub releases; "
            "if that step failed, install it manually from "
            "https://github.com/google/osv-scanner/releases."
        )

    started = time.time()
    evidence.log("TOOL_CALL", tool="osv-scanner", target=config.target_origin, candidates=list(manifests))

    manifests_found: list[str] = []
    vulnerabilities: list[OsvVulnerability] = []
    error: str | None = None

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for filename in manifests:
            url = config.target_origin + "/" + filename
            try:
                resp = requests.get(url, timeout=config.request_timeout_s, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp.status_code != 200 or not resp.content:
                continue

            manifests_found.append(filename)
            local_path = tmp_dir / filename
            local_path.write_bytes(resp.content)

            report_path = tmp_dir / f"{filename}.osv.json"
            cmd = ["osv-scanner", "scan", "source", "--format", "json", "--output", str(report_path), str(local_path)]
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max_scan_time_s,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                error = f"osv-scanner timed out scanning {filename}"
                continue

            if report_path.exists():
                try:
                    data = json.loads(report_path.read_text())
                    vulnerabilities.extend(_parse_osv_json(data, filename))
                except (json.JSONDecodeError, OSError) as exc:
                    error = f"failed to parse osv-scanner output for {filename}: {exc}"

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="osv-scanner",
        manifests_found=manifests_found,
        vulnerability_count=len(vulnerabilities),
        duration_s=duration,
        error=error,
    )

    return OsvResult(
        target=config.target_origin,
        manifests_checked=len(manifests),
        manifests_found=manifests_found,
        vulnerabilities=vulnerabilities,
        duration_s=duration,
        error=error,
    )
