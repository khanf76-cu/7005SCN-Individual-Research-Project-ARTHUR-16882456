"""Scoped directory / path brute-force tool.

Walks a wordlist of common paths against the authorized target, using the
same scoped_request primitive the HTTP tool uses (so every single request
still goes through RunConfig.is_in_scope()). Deliberately simple
request-per-path logic rather than high concurrency, so request-rate
stays predictable and polite against a small test target.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .http_tool import scoped_request

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "common_paths.txt"

# Status codes that indicate "something is actually here", as opposed to
# the target's own default 404 page. Many apps return 200 for a 404 page
# too, so a hit is also cross-checked against a baseline 404 response
# length/hash where possible.
INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403}


@dataclass
class DirBruteHit:
    path: str
    status_code: int | None
    elapsed_s: float
    body_sha256: str
    note: str = ""


@dataclass
class DirBruteResult:
    target: str
    hits: list[DirBruteHit] = field(default_factory=list)
    paths_tried: int = 0
    duration_s: float = 0.0


def run_dirbrute(
    config: RunConfig,
    evidence: EvidenceLogger,
    *,
    wordlist_path: Path = DEFAULT_WORDLIST,
    delay_s: float = 0.05,
    max_paths: int = 200,
) -> DirBruteResult:
    started = time.time()
    words = [
        w.strip()
        for w in wordlist_path.read_text(encoding="utf-8").splitlines()
        if w.strip() and not w.startswith("#")
    ][:max_paths]

    evidence.log("TOOL_CALL", tool="dirbrute", target=config.target_origin, word_count=len(words))

    # Baseline: request a near-certainly-nonexistent path to learn what
    # this app's "not found" response looks like, so we don't report
    # every word as a hit on an app that 200s everything (common on SPAs).
    baseline = scoped_request(
        config, evidence, method="GET", path="/__definitely-not-a-real-path-xyz123__"
    )

    hits: list[DirBruteHit] = []
    tried = 0
    for word in words:
        tried += 1
        path = word if word.startswith("/") else f"/{word}"
        res = scoped_request(config, evidence, method="GET", path=path)
        time.sleep(delay_s)

        if res.status_code is None:
            continue
        if res.status_code not in INTERESTING_STATUS:
            continue
        # Skip if it looks identical to the baseline 404-equivalent page.
        if (
            res.status_code == baseline.status_code
            and res.body_sha256 == baseline.body_sha256
            and baseline.body_sha256 != ""
        ):
            continue

        hits.append(
            DirBruteHit(
                path=path,
                status_code=res.status_code,
                elapsed_s=res.elapsed_s,
                body_sha256=res.body_sha256,
                note="differs from baseline 404 response",
            )
        )

    duration = time.time() - started
    evidence.log("TOOL_RESULT", tool="dirbrute", hit_count=len(hits), paths_tried=tried, duration_s=duration)

    return DirBruteResult(
        target=config.target_origin,
        hits=hits,
        paths_tried=tried,
        duration_s=duration,
    )
