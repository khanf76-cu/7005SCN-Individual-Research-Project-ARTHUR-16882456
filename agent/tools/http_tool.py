"""Scoped HTTP request tool.

A second, smaller tool alongside nikto so the agent can probe a specific
path/parameter the way a human tester would after reading a scan result
(e.g. following up on a nikto hit, or checking a ground-truth-style path
like /ftp/). Every request is scope-checked and logged before it is sent.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .nikto_tool import ScopeViolation

MAX_BODY_BYTES = 8000  # keep evidence files and LLM context manageable


@dataclass
class HttpResult:
    method: str
    url: str
    status_code: int | None
    elapsed_s: float
    body_excerpt: str
    body_sha256: str
    error: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


def scoped_request(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    data: str | None = None,
) -> HttpResult:
    import hashlib

    url = config.target_origin + ("" if path.startswith("/") else "/") + path
    if not config.is_in_scope(url):
        raise ScopeViolation(f"URL {url!r} is outside authorized scope")

    evidence.log("TOOL_CALL", tool="http", method=method, url=url)

    started = time.time()
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            data=data,
            timeout=config.request_timeout_s,
            allow_redirects=False,  # agent decides whether to follow, in-scope only
        )
        elapsed = time.time() - started
        body = resp.content[:MAX_BODY_BYTES]
        body_sha256 = hashlib.sha256(resp.content).hexdigest()
        try:
            resp_headers = dict(resp.headers) if resp.headers else {}
        except (TypeError, ValueError):
            # A test double or malformed response whose .headers isn't a
            # real mapping -- headers are a bonus signal, never worth
            # failing the request over.
            resp_headers = {}
        result = HttpResult(
            method=method,
            url=url,
            status_code=resp.status_code,
            elapsed_s=elapsed,
            body_excerpt=body.decode("utf-8", errors="replace"),
            body_sha256=body_sha256,
            headers=resp_headers,
        )
    except requests.RequestException as exc:
        elapsed = time.time() - started
        result = HttpResult(
            method=method,
            url=url,
            status_code=None,
            elapsed_s=elapsed,
            body_excerpt="",
            body_sha256="",
            error=str(exc),
        )

    evidence.log(
        "TOOL_RESULT",
        tool="http",
        url=url,
        status_code=result.status_code,
        elapsed_s=result.elapsed_s,
        body_sha256=result.body_sha256,
        body_len=len(result.body_excerpt),
        error=result.error,
    )
    return result
