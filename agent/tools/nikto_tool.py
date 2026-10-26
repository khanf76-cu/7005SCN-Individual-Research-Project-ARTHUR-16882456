"""Scoped nikto wrapper.

Runs the real `nikto` binary as a subprocess (no reimplementation of its
scanning logic -- nikto itself is the open-source tool; this module is
the original scoping/parsing wrapper that makes it safe for an autonomous
agent to call). Refuses to run against anything outside RunConfig's
allowed hosts, and parses nikto's `-Format xml` output into a small,
agent-friendly structure instead of raw text.

Why XML and not JSON: the Debian/Ubuntu `nikto` package (2.1.5, the
version `apt install nikto` gives you as of this writing) does not
support `-Format json` at all -- that was only added upstream in nikto
2.1.6. Asking for it makes nikto print "+ ERROR: Invalid output format"
and exit almost immediately with returncode 0 (not a failure exit code),
which previously made this tool silently report "0 findings" as if the
scan had run cleanly. `-Format csv` works but this nikto version has its
own bug where the IP column gets corrupted with a stray Perl
`SCALAR(0x...)` reference, which breaks clean CSV parsing. `-Format xml`
is the stable, well-structured option nikto actually gets right.

One more environment-specific wrinkle: nikto's XML writer refuses to run
unless it can read a DTD file at the path configured in
`/etc/nikto/config.txt`'s `NIKTODTD=` setting (normally
`/usr/share/doc/nikto/nikto.dtd`). On minimal/cloud Ubuntu images,
`/usr/share/doc/*` is often stripped by a dpkg policy
(`/etc/dpkg/dpkg.cfg.d/*`), which deletes that file even though nikto
still points at it -- a packaging bug in nikto's own .deb. nikto only
checks that the file exists and is readable; it never parses or
validates against its contents (it's just substituted as a path string
into the output's DOCTYPE declaration), so `_ensure_nikto_dtd_readable()`
below self-heals this by writing a harmless placeholder file there if
it's missing. `setup.sh` does the same thing at install time; this is a
second, defensive copy so the tool keeps working even if that file gets
stripped again later (e.g. by an unattended `apt upgrade`).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from ..config import RunConfig
from ..evidence import EvidenceLogger

NIKTO_CONFIG_PATH = Path("/etc/nikto/config.txt")
_NIKTODTD_RE = re.compile(r"^\s*NIKTODTD\s*=\s*(\S+)\s*$")
_ERROR_LINE_RE = re.compile(r"^\+\s*ERROR:.*$", re.MULTILINE)
_ITEM_BLOCK_RE = re.compile(r"<item\b.*?</item>", re.DOTALL)


class ScopeViolation(Exception):
    pass


@dataclass
class NiktoFinding:
    id: str
    osvdb: str | None
    method: str
    url: str
    message: str


@dataclass
class NiktoResult:
    target: str
    findings: list[NiktoFinding]
    raw_stdout: str
    returncode: int
    duration_s: float
    truncated: bool
    error: str | None = None


def nikto_available() -> bool:
    return shutil.which("nikto") is not None


def _ensure_nikto_dtd_readable() -> None:
    """Best-effort self-heal for the missing-DTD packaging bug described
    in the module docstring. Never raises -- if this can't fix things
    (no permission, non-Debian install, config laid out differently),
    nikto's own "+ ERROR: reading DTD" is still caught by
    `_detect_error()` below, so the failure surfaces instead of being
    silently swallowed."""
    try:
        if not NIKTO_CONFIG_PATH.exists():
            return
        dtd_path = None
        for line in NIKTO_CONFIG_PATH.read_text().splitlines():
            m = _NIKTODTD_RE.match(line)
            if m:
                dtd_path = Path(m.group(1))
                break
        if dtd_path is None or dtd_path.exists():
            return
        dtd_path.parent.mkdir(parents=True, exist_ok=True)
        dtd_path.write_text(
            "<!-- placeholder: nikto only checks that this file exists and "
            "is readable, it never parses or validates against it -->\n"
        )
        dtd_path.chmod(0o644)
    except OSError:
        pass  # best-effort only; see _detect_error() for the real safety net


def _detect_error(proc: subprocess.CompletedProcess, out_path: Path) -> str | None:
    """Looks for the ways nikto fails *without* a non-zero exit code
    (this version exits 0 even on "+ ERROR: ..." conditions), so a tool
    failure is reported as an error instead of looking like a clean
    0-finding scan."""
    stdout = proc.stdout or ""
    error_match = _ERROR_LINE_RE.search(stdout)
    if error_match:
        return f"nikto reported an error: {error_match.group().strip()}"
    if proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip()[-300:]
        return f"nikto exited with returncode {proc.returncode}: {stderr_tail}"
    if not out_path.exists():
        return "nikto exited cleanly but produced no output file"
    return None


def _recover_items_from_truncated_xml(xml_text: str) -> list[ET.Element]:
    """Best-effort recovery when the full document won't parse.

    nikto's `-maxtime` cutoff (or the target simply going unresponsive
    mid-scan, which is exactly what a heavily-loaded local target under
    ARTHUR's own concurrent 8-sub-tool VA pass can trigger) can leave the
    output file truncated -- missing its closing `</scandetails>
    </niktoscan>` tags, or even cut off mid-`<item>`. That shouldn't
    throw away every finding nikto DID manage to write out just because
    the document as a whole is incomplete: pull out each individually
    well-formed `<item>...</item>` block directly and parse those on
    their own. Any trailing, genuinely incomplete item has no matching
    closing tag for the regex to find, so it's silently dropped rather
    than taking the whole scan down with it.
    """
    items: list[ET.Element] = []
    for block in _ITEM_BLOCK_RE.findall(xml_text):
        try:
            items.append(ET.fromstring(block))
        except ET.ParseError:
            continue  # this one specific item is itself corrupted -- skip just it
    return items


def _parse_nikto_xml(xml_text: str, fallback_target: str) -> tuple[list[NiktoFinding], bool]:
    """Returns (findings, recovered) -- `recovered` is True when the
    document didn't parse cleanly and findings (if any) came from the
    per-item fallback in `_recover_items_from_truncated_xml` instead."""
    recovered = False
    try:
        root = ET.fromstring(xml_text)
        items = list(root.iter("item"))
    except ET.ParseError:
        items = _recover_items_from_truncated_xml(xml_text)
        recovered = True

    findings: list[NiktoFinding] = []
    for i, item in enumerate(items):
        description_el = item.find("description")
        uri_el = item.find("uri")
        namelink_el = item.find("namelink")
        findings.append(
            NiktoFinding(
                id=item.get("id") or f"nikto-{i:04d}",
                osvdb=item.get("osvdbid"),
                method=item.get("method", "GET"),
                url=(namelink_el.text if namelink_el is not None and namelink_el.text else None)
                or (uri_el.text if uri_el is not None else None)
                or fallback_target,
                message=(description_el.text or "").strip() if description_el is not None else "",
            )
        )
    return findings, recovered


def run_nikto(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    tuning: str | None = None,
    max_scan_time_s: int = 120,
) -> NiktoResult:
    """Run nikto against config.target_origin and return parsed findings.

    `tuning` maps to nikto's `-Tuning` option (e.g. "1" for interesting
    files, "9" for SQL injection) so the LLM agent can ask for a focused
    pass instead of always running the full default test set, which can
    be slow against a single Juice Shop instance.
    """
    if not config.is_in_scope(config.target_origin):
        raise ScopeViolation(f"Target {config.target_origin!r} is not in allowed scope")
    if not nikto_available():
        raise RuntimeError(
            "nikto is not on PATH. Install it (e.g. `apt install nikto` or "
            "`brew install nikto`) before running this tool."
        )

    _ensure_nikto_dtd_readable()

    import time

    started = time.time()

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "nikto_out.xml"
        cmd = [
            "nikto",
            "-h",
            config.target_origin,
            "-Format",
            "xml",
            "-output",
            str(out_path),
            "-maxtime",
            str(max_scan_time_s),
            "-ask",
            "no",
        ]
        if tuning:
            cmd += ["-Tuning", tuning]

        evidence.log(
            "TOOL_CALL",
            tool="nikto",
            command=cmd,
            target=config.target_origin,
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_scan_time_s + 30,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            evidence.log("TOOL_ERROR", tool="nikto", error="timeout")
            return NiktoResult(
                target=config.target_origin,
                findings=[],
                raw_stdout=(exc.stdout or ""),
                returncode=-1,
                duration_s=time.time() - started,
                truncated=True,
                error="nikto timed out",
            )

        findings: list[NiktoFinding] = []
        truncated = False
        error = _detect_error(proc, out_path)

        if error is None:
            try:
                findings, recovered = _parse_nikto_xml(out_path.read_text(), config.target_origin)
                if recovered:
                    truncated = True
                    if findings:
                        # Not a hard failure -- we still got real findings,
                        # just flag that the underlying scan was cut short
                        # (commonly because of contention against a heavily
                        # loaded local target) so that's visible rather than
                        # silently implied by a suspiciously round number.
                        error = (
                            f"nikto's XML output was truncated (scan likely interrupted mid-run); "
                            f"recovered {len(findings)} finding(s) from the complete items it did write out"
                        )
                    else:
                        error = "nikto's XML output was truncated and no complete findings could be recovered from it"
            except OSError as exc:
                truncated = True
                error = f"failed to read nikto XML output: {exc}"

        duration = time.time() - started
        evidence.log(
            "TOOL_RESULT",
            tool="nikto",
            returncode=proc.returncode,
            finding_count=len(findings),
            duration_s=duration,
            error=error,
        )

        return NiktoResult(
            target=config.target_origin,
            findings=findings,
            raw_stdout=proc.stdout,
            returncode=proc.returncode,
            duration_s=duration,
            truncated=truncated,
            error=error,
        )
