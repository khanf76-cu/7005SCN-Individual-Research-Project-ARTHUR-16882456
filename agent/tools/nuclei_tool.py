"""Scoped nuclei wrapper (OWASP A02 - Security Misconfiguration, plus
known-CVE template coverage).

nuclei (github.com/projectdiscovery/nuclei) isn't apt-packaged -- setup.sh
downloads a pinned prebuilt release binary from GitHub, and separately
runs `nuclei -update-templates` once at install time to populate its
template set (a large community-maintained library of YAML vulnerability
checks). Both of those are best-effort, non-fatal steps in setup.sh: if
either one fails (e.g. a changed release asset name, or no outbound
network to GitHub at install time), `nuclei_available()` below reports
the tool as absent and the VA agent skips it cleanly, the same way an
unreachable `nmap`/`nikto` binary is already handled -- the rest of the
scan still runs and the report says plainly that this tool didn't run,
rather than silently missing a whole scanner.

`-duc` (disable update check) keeps scan time deterministic by not
letting nuclei try to pull template updates mid-scan; template updates
are setup.sh's job, once, not something to repeat on every run.
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

DEFAULT_SEVERITIES = "low,medium,high,critical"


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    description: str
    matched_at: str
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class NucleiResult:
    target: str
    findings: list[NucleiFinding] = field(default_factory=list)
    duration_s: float = 0.0
    truncated: bool = False
    error: str | None = None


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _parse_jsonl(path: Path) -> list[NucleiFinding]:
    findings: list[NucleiFinding] = []
    if not path.exists():
        return findings
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        findings.append(
            NucleiFinding(
                template_id=obj.get("template-id", ""),
                name=info.get("name", ""),
                severity=(info.get("severity") or "info").lower(),
                description=info.get("description", "") or "",
                matched_at=obj.get("matched-at", obj.get("host", "")),
                cve_ids=list(cve_ids) if isinstance(cve_ids, list) else [cve_ids],
            )
        )
    return findings


def run_nuclei(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    severities: str = DEFAULT_SEVERITIES,
    rate_limit: int = 50,
    max_scan_time_s: int = 180,
) -> NucleiResult:
    if not config.is_in_scope(config.target_origin):
        raise ScopeViolation(f"Target {config.target_origin!r} is not in allowed scope")
    if not nuclei_available():
        raise RuntimeError(
            "nuclei is not on PATH. setup.sh downloads it from GitHub releases; "
            "if that step failed (e.g. no network to GitHub at install time), "
            "install it manually from https://github.com/projectdiscovery/nuclei/releases "
            "and run `nuclei -update-templates` once."
        )

    started = time.time()

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "nuclei_out.jsonl"
        cmd = [
            "nuclei",
            "-u",
            config.target_origin,
            "-jsonl",
            "-o",
            str(out_path),
            "-severity",
            severities,
            "-rl",
            str(rate_limit),
            "-duc",  # disable the template auto-update check for a deterministic scan
            "-silent",
            "-nc",  # no color codes in any stdout nuclei still emits
        ]

        evidence.log("TOOL_CALL", tool="nuclei", command=cmd, target=config.target_origin)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_scan_time_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            evidence.log("TOOL_ERROR", tool="nuclei", error="timeout")
            return NucleiResult(
                target=config.target_origin,
                findings=_parse_jsonl(out_path),  # keep whatever was written before the timeout
                duration_s=time.time() - started,
                truncated=True,
                error="nuclei timed out",
            )

        findings = _parse_jsonl(out_path)
        error = None
        if proc.returncode != 0 and not out_path.exists():
            stderr_tail = (proc.stderr or "").strip()[-300:]
            error = f"nuclei exited with returncode {proc.returncode}: {stderr_tail}"

        duration = time.time() - started
        evidence.log(
            "TOOL_RESULT",
            tool="nuclei",
            returncode=proc.returncode,
            finding_count=len(findings),
            duration_s=duration,
            error=error,
        )

        return NucleiResult(
            target=config.target_origin,
            findings=findings,
            duration_s=duration,
            truncated=False,
            error=error,
        )
