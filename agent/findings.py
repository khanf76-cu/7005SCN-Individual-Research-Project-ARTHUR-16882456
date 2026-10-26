"""Shared finding schema used by every agent.

A single normalised shape means the correlate agent doesn't need
per-agent parsing logic to merge recon/nmap/va output -- each agent
emits a list of these, and correlate just deduplicates and enriches.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    source_agent: str  # "recon" | "nmap" | "va" | "correlate"
    title: str
    category: str  # e.g. "exposed_path", "open_port", "service_version", "http_vuln"
    severity: str  # info | low | medium | high | critical
    confidence: str  # confirmed | suspected
    endpoint: str  # path, host:port, or URL -- whatever identifies the target item
    evidence: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
