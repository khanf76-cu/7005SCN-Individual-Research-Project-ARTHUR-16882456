"""Scoped sqlmap wrapper (OWASP A05 - Injection).

Runs the real `sqlmap` binary (apt-installable: `apt install sqlmap`)
against the target. Rather than requiring tight coupling to what
recon_agent happened to discover, this uses sqlmap's own `--crawl` mode
so it self-discovers query-parameterised links up to a shallow depth and
tests each one, as well as any query parameter already present on the
target URL itself -- the same approach a human tester would reach for
first. `--level=1 --risk=1` are sqlmap's lowest/safest test intensity
(fewer requests, no risk-of-data-modification payloads), appropriate for
an unattended agent with no one watching each request it sends.

Deliberately does NOT pass `--forms`: that flag makes sqlmap test *only*
HTML forms found on the crawled pages and skip testing the target URL's
own query parameters entirely (confirmed by direct testing -- `sqlmap -u
'<url>?id=1' --forms` reports "no forms found" and never touches `id`,
even though `id` is directly injectable). Form-based injection is a real
gap this leaves uncovered, but silently losing direct-URL-parameter
coverage to chase it would be a worse trade for a VA agent that's
supposed to also catch the simple case.

If the crawl finds nothing to test (common on single-page apps, JS-heavy
frontends, or sites with no linked query parameters), sqlmap exits
cleanly having written no results file at all -- that is a legitimate
"nothing testable found" outcome, not a tool failure, and is reported as
zero findings rather than an error.
"""
from __future__ import annotations

import csv
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation


@dataclass
class SqlmapFinding:
    url: str
    place: str  # e.g. "GET", "POST"
    parameter: str
    techniques: str  # sqlmap's technique letter code, e.g. "BTU" = Boolean/Time/UNION-based
    note: str


@dataclass
class SqlmapResult:
    target: str
    findings: list[SqlmapFinding] = field(default_factory=list)
    duration_s: float = 0.0
    truncated: bool = False
    error: str | None = None


def sqlmap_available() -> bool:
    return shutil.which("sqlmap") is not None


def _parse_results_csv(out_dir: Path) -> list[SqlmapFinding]:
    findings: list[SqlmapFinding] = []
    for csv_path in out_dir.glob("results-*.csv"):
        with csv_path.open(newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                findings.append(
                    SqlmapFinding(
                        url=row.get("Target URL", ""),
                        place=row.get("Place", ""),
                        parameter=row.get("Parameter", ""),
                        techniques=row.get("Technique(s)", ""),
                        note=row.get("Note(s)", ""),
                    )
                )
    return findings


def run_sqlmap(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    crawl_depth: int = 2,
    max_scan_time_s: int = 180,
) -> SqlmapResult:
    if not config.is_in_scope(config.target_origin):
        raise ScopeViolation(f"Target {config.target_origin!r} is not in allowed scope")
    if not sqlmap_available():
        raise RuntimeError(
            "sqlmap is not on PATH. Install it (e.g. `apt install sqlmap`) before running this tool."
        )

    started = time.time()

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        cmd = [
            "sqlmap",
            "-u",
            config.target_origin,
            "--crawl",
            str(crawl_depth),
            "--batch",
            "--level=1",
            "--risk=1",
            "--output-dir",
            str(out_dir),
            "--disable-coloring",
            "-v",
            "0",
        ]

        evidence.log("TOOL_CALL", tool="sqlmap", command=cmd, target=config.target_origin)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_scan_time_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            evidence.log("TOOL_ERROR", tool="sqlmap", error="timeout")
            return SqlmapResult(
                target=config.target_origin,
                findings=[],
                duration_s=time.time() - started,
                truncated=True,
                error="sqlmap timed out",
            )

        findings = _parse_results_csv(out_dir)

        duration = time.time() - started
        evidence.log(
            "TOOL_RESULT",
            tool="sqlmap",
            returncode=proc.returncode,
            finding_count=len(findings),
            duration_s=duration,
        )

        return SqlmapResult(
            target=config.target_origin,
            findings=findings,
            duration_s=duration,
            truncated=False,
            error=None,
        )
