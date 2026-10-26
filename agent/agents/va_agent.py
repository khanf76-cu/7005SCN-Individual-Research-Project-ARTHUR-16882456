"""VA (vulnerability assessment) agent: multi-tool web vulnerability scan.

Originally a thin wrapper around nikto alone. Nikto is a signature/
known-file scanner -- it doesn't actively fuzz inputs, so it structurally
cannot find things like SQL injection or reflected XSS. Rather than rely
on one tool (and, per the bug this session started by fixing, one tool
that can fail silently), VA agent now runs eight independent checks
concurrently and normalises all of their output into the shared Finding
schema:

  1. nikto_tool     known-vuln/misconfig signature scan
  2. tls_tool       TLS protocol/certificate hygiene (A04)
  3. cookie_tool    session-cookie attribute check (partial A07)
  4. sqlmap_tool    confirmed SQL injection (A05)
  5. wapiti_tool    active input-fuzzing DAST: XSS/SQLi/SSRF-adjacent/etc.
  6. nuclei_tool    community CVE/misconfig template matching (A02)
  7. osv_tool       opportunistic dependency-CVE check from exposed manifests (A03)
  8. zap_tool       OWASP ZAP spider + active scan, broadest single-tool coverage

Three of these (nuclei, osv-scanner, zap) depend on a binary setup.sh
downloads best-effort from GitHub releases -- if that download failed on
a given install (no network to GitHub at install time, a changed release
asset name, etc.), that sub-tool's `*_available()` check reports it
absent and it's skipped here with a clear message, rather than taking
down the whole VA pass. `tool_errors` on VaAgentResult carries one entry
per sub-tool that didn't run cleanly (unavailable, errored, or timed
out), keyed by tool name, so a 0-finding VA stage can always be told
apart from a VA stage where something actually failed -- the whole
reason this module was rewritten in the first place (see nikto_tool.py's
docstring for that history).

Running all eight concurrently (rather than one after another) keeps the
wall-clock cost close to the slowest single tool (usually ZAP's active
scan) instead of their sum, matching the "every agent runs its tools
simultaneously" design already used at the orchestrator level for
recon/nmap/va themselves.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..config import RunConfig
from ..evidence import EvidenceLogger
from ..findings import Finding
from ..tools.cookie_tool import run_cookie_check
from ..tools.nikto_tool import run_nikto
from ..tools.nuclei_tool import nuclei_available, run_nuclei
from ..tools.osv_tool import osv_scanner_available, run_osv_check
from ..tools.sqlmap_tool import run_sqlmap
from ..tools.tls_tool import run_tls_check
from ..tools.wapiti_tool import run_wapiti
from ..tools.zap_tool import run_zap, zap_available

# nikto/sqlmap/wapiti message keywords that typically indicate a more
# serious class of finding, used only to set an initial severity
# estimate -- the correlate agent is where real triage happens.
HIGH_SIGNAL_KEYWORDS = (
    "sql injection",
    "remote code execution",
    "command injection",
    "xxe",
    "default credential",
    "authentication bypass",
)

# Normalises each sub-tool's own severity vocabulary into ARTHUR's
# five-level scheme (critical/high/medium/low/info).
_SEVERITY_NORMALIZE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}

_WAPITI_CATEGORY_SEVERITY = {
    "SQL Injection": "high",
    "Command execution": "high",
    "CRLF Injection": "medium",
    "Reflected Cross Site Scripting": "medium",
    "Stored Cross Site Scripting": "high",
    "Cross Site Request Forgery": "medium",
    "htaccess Bypass": "medium",
    "Open Redirect": "low",
    "Backup file": "medium",
}


def _normalize_severity(raw: str | None) -> str:
    return _SEVERITY_NORMALIZE.get((raw or "info").strip().lower(), "info")


@dataclass
class VaAgentResult:
    findings: list[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    tool_errors: dict[str, str] = field(default_factory=dict)
    tools_run: list[str] = field(default_factory=list)


def _run_nikto_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    r = run_nikto(config, evidence)
    findings: list[Finding] = []
    for f in r.findings:
        message_lower = f.message.lower()
        severity = "high" if any(k in message_lower for k in HIGH_SIGNAL_KEYWORDS) else "low"
        findings.append(
            Finding(
                source_agent="va",
                title=f.message[:120] if f.message else f"nikto finding {f.id}",
                category="http_vuln",
                severity=severity,
                confidence="suspected",
                endpoint=f.url,
                evidence=f"nikto ({f.method} {f.url}): {f.message}" + (f" [OSVDB: {f.osvdb}]" if f.osvdb else ""),
                extra={"tool": "nikto", "nikto_id": f.id, "osvdb": f.osvdb, "method": f.method},
            )
        )
    return findings, r.error


def _run_tls_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    r = run_tls_check(config, evidence)
    if not r.applicable:
        return [], None
    severity_by_kind = {
        "expired_cert": "high",
        "self_signed": "medium",
        "untrusted": "medium",
        "hostname_mismatch": "medium",
        "weak_protocol": "medium",
        "expiring_soon": "low",
    }
    findings = [
        Finding(
            source_agent="va",
            title=f"TLS issue: {issue.kind.replace('_', ' ')}",
            category="tls",
            severity=severity_by_kind.get(issue.kind, "low"),
            confidence="confirmed",
            endpoint=f"{r.target_host}:{r.target_port}",
            evidence=issue.detail,
            extra={"tool": "tls", "negotiated_protocol": r.negotiated_protocol},
        )
        for issue in r.issues
    ]
    return findings, r.error


def _run_cookie_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    r = run_cookie_check(config, evidence)
    severity_by_attr = {"Secure": "medium", "HttpOnly": "medium", "SameSite": "low"}
    findings = [
        Finding(
            source_agent="va",
            title=f"Cookie '{issue.cookie_name}' missing {issue.missing_attribute}",
            category="cookie_attribute",
            severity=severity_by_attr.get(issue.missing_attribute, "low"),
            confidence="confirmed",
            endpoint=r.checked_url,
            evidence=issue.detail,
            extra={"tool": "cookies"},
        )
        for issue in r.issues
    ]
    return findings, r.error


def _run_sqlmap_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    r = run_sqlmap(config, evidence)
    findings = [
        Finding(
            source_agent="va",
            title=f"SQL injection: parameter '{f.parameter}' ({f.place})",
            category="sql_injection",
            severity="high",
            confidence="confirmed",
            endpoint=f.url,
            evidence=f"sqlmap confirmed injection via {f.place} parameter '{f.parameter}' "
            f"(technique(s): {f.techniques}). {f.note}".strip(),
            extra={"tool": "sqlmap", "techniques": f.techniques},
        )
        for f in r.findings
    ]
    return findings, r.error


def _run_wapiti_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    r = run_wapiti(config, evidence)
    findings = [
        Finding(
            source_agent="va",
            title=f"{f.category}: {f.path}",
            category="webapp_vuln",
            severity=_WAPITI_CATEGORY_SEVERITY.get(f.category, "medium"),
            confidence="suspected",
            endpoint=f"{f.method} {f.path}" + (f" (param: {f.parameter})" if f.parameter else ""),
            evidence=f.info,
            extra={"tool": "wapiti", "module": f.module},
        )
        for f in r.findings
    ]
    return findings, r.error


def _run_nuclei_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    if not nuclei_available():
        return [], "nuclei is not installed (setup.sh's best-effort download may have failed; see its docstring)"
    r = run_nuclei(config, evidence)
    findings = [
        Finding(
            source_agent="va",
            title=f.name or f.template_id,
            category="template_match",
            severity=_normalize_severity(f.severity),
            confidence="suspected",
            endpoint=f.matched_at,
            evidence=f.description or f"Matched nuclei template '{f.template_id}'",
            extra={"tool": "nuclei", "template_id": f.template_id, "cve_ids": f.cve_ids},
        )
        for f in r.findings
    ]
    return findings, r.error


def _run_osv_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    if not osv_scanner_available():
        return [], "osv-scanner is not installed (setup.sh's best-effort download may have failed; see its docstring)"
    r = run_osv_check(config, evidence)
    findings = [
        Finding(
            source_agent="va",
            title=f"{v.vuln_id}: {v.package_name}@{v.package_version}",
            category="dependency_vuln",
            severity=_normalize_severity(v.severity),
            confidence="confirmed",
            endpoint=f"/{v.manifest_file}",
            evidence=(v.summary or f"Known vulnerability {v.vuln_id} in {v.package_name} {v.package_version}")
            + f" (exposed manifest: {v.manifest_file})",
            extra={"tool": "osv-scanner", "ecosystem": v.ecosystem, "vuln_id": v.vuln_id},
        )
        for v in r.vulnerabilities
    ]
    return findings, r.error


def _run_zap_findings(config: RunConfig, evidence: EvidenceLogger) -> tuple[list[Finding], str | None]:
    if not zap_available():
        return [], "ZAP is not installed (setup.sh's best-effort download may have failed; see its docstring)"
    r = run_zap(config, evidence)
    findings = [
        Finding(
            source_agent="va",
            title=a.name,
            category="webapp_vuln",
            severity=_normalize_severity(a.risk),
            confidence="confirmed" if (a.confidence or "").lower() == "high" else "suspected",
            endpoint=a.url + (f" (param: {a.param})" if a.param else ""),
            evidence=a.description or a.name,
            extra={"tool": "zap", "solution": a.solution, "cwe_id": a.cwe_id},
        )
        for a in r.alerts
    ]
    return findings, r.error


# name -> (worker fn, whether it's a "best-effort binary" sub-tool whose
# absence is expected/non-fatal rather than a real failure)
_SUB_TOOLS: dict[str, tuple] = {
    "nikto": (_run_nikto_findings, False),
    "tls": (_run_tls_findings, False),
    "cookies": (_run_cookie_findings, False),
    "sqlmap": (_run_sqlmap_findings, False),
    "wapiti": (_run_wapiti_findings, False),
    "nuclei": (_run_nuclei_findings, True),
    "osv-scanner": (_run_osv_findings, True),
    "zap": (_run_zap_findings, True),
}


def run_va_agent(config: RunConfig, evidence: EvidenceLogger) -> VaAgentResult:
    started = time.time()
    evidence.log("AGENT_START", agent="va", sub_tools=list(_SUB_TOOLS))

    findings: list[Finding] = []
    tool_errors: dict[str, str] = {}
    tools_run: list[str] = []

    def _run_one(name: str, fn):
        try:
            tool_findings, tool_error = fn(config, evidence)
            return name, tool_findings, tool_error
        except RuntimeError as exc:
            # Binary not on PATH -- expected for the best-effort GitHub-downloaded
            # tools if setup.sh's download step failed; a real failure for the
            # apt/pip-installed ones.
            return name, [], str(exc)
        except Exception as exc:  # noqa: BLE001 -- isolate one sub-tool's failure from the rest
            return name, [], f"unexpected error: {exc}"

    with ThreadPoolExecutor(max_workers=len(_SUB_TOOLS)) as pool:
        futures = [pool.submit(_run_one, name, fn) for name, (fn, _) in _SUB_TOOLS.items()]
        for fut in futures:
            name, tool_findings, tool_error = fut.result()
            findings.extend(tool_findings)
            tools_run.append(name)
            if tool_error:
                tool_errors[name] = tool_error

    result = VaAgentResult(
        findings=findings,
        duration_s=time.time() - started,
        tool_errors=tool_errors,
        tools_run=tools_run,
    )
    evidence.log(
        "AGENT_END",
        agent="va",
        finding_count=len(findings),
        duration_s=result.duration_s,
        tool_errors=tool_errors,
    )
    return result
