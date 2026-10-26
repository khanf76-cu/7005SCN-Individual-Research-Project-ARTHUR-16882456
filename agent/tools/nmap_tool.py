"""Scoped nmap wrapper: service/version detection + NSE vulnerability scripts.

Uses `-sT` (TCP connect scan) rather than `-sS` (SYN scan) so it runs
without root privileges on most setups -- appropriate for a student lab
environment where you may not have sudo on the scanning host. Uses
`--script vuln,safe` rather than the full NSE script set: `vuln` covers
the vulnerability-detection scripts (the reason nmap is here at all),
and `safe` keeps out scripts nmap itself classifies as intrusive/risky
(brute-force, DoS-adjacent). This is a deliberate safety choice for an
automated agent with no human watching each script run -- document it as
such in your report.

Scope is checked against the target host only (nmap operates on
host:port, not full URLs), using the same RunConfig.allowed_hosts the
other tools use.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation


@dataclass
class NmapService:
    port: int
    protocol: str
    state: str
    service_name: str
    product: str | None
    version: str | None
    cpe: list[str] = field(default_factory=list)


@dataclass
class NmapScriptHit:
    port: int | None  # None for host-level scripts
    script_id: str
    output: str


@dataclass
class NmapResult:
    target_host: str
    services: list[NmapService] = field(default_factory=list)
    script_hits: list[NmapScriptHit] = field(default_factory=list)
    raw_returncode: int = 0
    duration_s: float = 0.0
    truncated: bool = False


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    top_ports: int = 200,
    extra_ports: str | None = None,
    script_categories: str = "vuln,safe",
    max_scan_time_s: int = 300,
) -> NmapResult:
    target_host = urlparse(config.target_origin).hostname or ""
    if target_host not in config.allowed_hosts:
        raise ScopeViolation(f"Host {target_host!r} is not in allowed scope for nmap")
    if not nmap_available():
        raise RuntimeError(
            "nmap is not on PATH. Install it (e.g. `apt install nmap` or "
            "`brew install nmap`) before running this tool."
        )

    started = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "nmap_out.xml"
        cmd = [
            "nmap",
            "-sT",
            "-sV",
            "--script",
            script_categories,
            "-oX",
            str(out_path),
            "--host-timeout",
            f"{max_scan_time_s}s",
        ]
        if extra_ports:
            cmd += ["-p", extra_ports]
        else:
            cmd += ["--top-ports", str(top_ports)]
        cmd.append(target_host)

        evidence.log("TOOL_CALL", tool="nmap", command=cmd, target=target_host)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_scan_time_s + 60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            evidence.log("TOOL_ERROR", tool="nmap", error="timeout")
            return NmapResult(
                target_host=target_host,
                raw_returncode=-1,
                duration_s=time.time() - started,
                truncated=True,
            )

        services: list[NmapService] = []
        script_hits: list[NmapScriptHit] = []
        truncated = False

        if out_path.exists():
            try:
                tree = ET.parse(out_path)
                root = tree.getroot()
                for host_el in root.findall("host"):
                    for ports_el in host_el.findall("ports"):
                        for port_el in ports_el.findall("port"):
                            port_num = int(port_el.get("portid", "0"))
                            protocol = port_el.get("protocol", "tcp")
                            state_el = port_el.find("state")
                            state = state_el.get("state") if state_el is not None else "unknown"

                            service_el = port_el.find("service")
                            service_name = service_el.get("name", "") if service_el is not None else ""
                            product = service_el.get("product") if service_el is not None else None
                            version = service_el.get("version") if service_el is not None else None
                            cpes = [c.text for c in port_el.findall("cpe") if c.text]

                            if state == "open":
                                services.append(
                                    NmapService(
                                        port=port_num,
                                        protocol=protocol,
                                        state=state,
                                        service_name=service_name,
                                        product=product,
                                        version=version,
                                        cpe=cpes,
                                    )
                                )

                            for script_el in port_el.findall("script"):
                                script_hits.append(
                                    NmapScriptHit(
                                        port=port_num,
                                        script_id=script_el.get("id", ""),
                                        output=(script_el.get("output", "") or "")[:2000],
                                    )
                                )

                    for hostscript_el in host_el.findall("hostscript"):
                        for script_el in hostscript_el.findall("script"):
                            script_hits.append(
                                NmapScriptHit(
                                    port=None,
                                    script_id=script_el.get("id", ""),
                                    output=(script_el.get("output", "") or "")[:2000],
                                )
                            )
            except (ET.ParseError, OSError):
                truncated = True

        duration = time.time() - started
        evidence.log(
            "TOOL_RESULT",
            tool="nmap",
            returncode=proc.returncode,
            open_port_count=len(services),
            script_hit_count=len(script_hits),
            duration_s=duration,
        )

        return NmapResult(
            target_host=target_host,
            services=services,
            script_hits=script_hits,
            raw_returncode=proc.returncode,
            duration_s=duration,
            truncated=truncated,
        )
