"""Nmap agent: service/version enumeration + NSE vulnerability scripts.

Normalises nmap's raw services and script hits into the shared Finding
schema. Open ports and detected versions are logged at info/low severity
(they're recon facts, not vulnerabilities on their own) while an NSE
script that actually reports a vulnerability (its output contains a CVE
ID or an explicit "VULNERABLE" marker, which nmap's vuln-category
scripts conventionally print) is raised to medium/high.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ..config import RunConfig
from ..evidence import EvidenceLogger
from ..findings import Finding
from ..tools.nmap_tool import run_nmap

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


@dataclass
class NmapAgentResult:
    findings: list[Finding] = field(default_factory=list)
    open_ports: int = 0
    duration_s: float = 0.0


def run_nmap_agent(config: RunConfig, evidence: EvidenceLogger) -> NmapAgentResult:
    started = time.time()
    evidence.log("AGENT_START", agent="nmap")

    nmap_result = run_nmap(config, evidence)
    findings: list[Finding] = []

    for svc in nmap_result.services:
        version_str = f"{svc.product or ''} {svc.version or ''}".strip()
        findings.append(
            Finding(
                source_agent="nmap",
                title=f"Open port {svc.port}/{svc.protocol}: {svc.service_name or 'unknown'}",
                category="service_version",
                severity="info",
                confidence="confirmed",
                endpoint=f"{nmap_result.target_host}:{svc.port}",
                evidence=f"nmap -sV detected {svc.service_name} "
                f"{('(' + version_str + ')') if version_str else ''} on "
                f"{svc.protocol}/{svc.port}, state={svc.state}",
                extra={
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "product": svc.product,
                    "version": svc.version,
                    "cpe": svc.cpe,
                },
            )
        )

    for hit in nmap_result.script_hits:
        cves_found = CVE_PATTERN.findall(hit.output)
        is_vulnerable_marker = "VULNERABLE" in hit.output.upper()
        severity = "high" if (cves_found or is_vulnerable_marker) else "info"
        confidence = "confirmed" if (cves_found or is_vulnerable_marker) else "suspected"

        findings.append(
            Finding(
                source_agent="nmap",
                title=f"NSE script result: {hit.script_id}",
                category="nse_script",
                severity=severity,
                confidence=confidence,
                endpoint=f"{nmap_result.target_host}:{hit.port}" if hit.port else nmap_result.target_host,
                evidence=hit.output[:1000],
                extra={"script_id": hit.script_id, "cves_mentioned": cves_found},
            )
        )

    result = NmapAgentResult(
        findings=findings,
        open_ports=len(nmap_result.services),
        duration_s=time.time() - started,
    )
    evidence.log("AGENT_END", agent="nmap", finding_count=len(findings), duration_s=result.duration_s)
    return result
