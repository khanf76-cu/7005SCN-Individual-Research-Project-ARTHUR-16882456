"""HTTP method enumeration via OPTIONS.

Sends a single scoped OPTIONS request to the target root and reads back
the `Allow` header most web servers/frameworks populate with the
methods that endpoint accepts. State-changing or debug methods left
enabled (PUT, DELETE, TRACE, CONNECT) are worth flagging -- not because
OPTIONS alone proves they're exploitable, but because an enabled method
a REST API didn't intend to expose is a common real-world
misconfiguration.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .http_tool import scoped_request

RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


@dataclass
class HttpMethodsResult:
    checked_url: str
    allowed_methods: list[str] = field(default_factory=list)
    risky_methods: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def run_http_methods_probe(config: RunConfig, evidence: EvidenceLogger) -> HttpMethodsResult:
    started = time.time()
    evidence.log("TOOL_CALL", tool="http_methods", target=config.target_origin)

    res = scoped_request(config, evidence, method="OPTIONS", path="/")
    allow_header = ""
    for key, value in (res.headers or {}).items():
        if key.lower() == "allow":
            allow_header = value
            break

    allowed = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    risky = [m for m in allowed if m in RISKY_METHODS]

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="http_methods",
        allowed_methods=allowed,
        risky_methods=risky,
        duration_s=duration,
    )

    return HttpMethodsResult(
        checked_url=res.url,
        allowed_methods=allowed,
        risky_methods=risky,
        duration_s=duration,
    )
