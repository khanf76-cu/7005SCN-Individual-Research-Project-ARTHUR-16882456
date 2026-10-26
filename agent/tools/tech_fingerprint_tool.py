"""Lightweight technology/CMS fingerprinting.

Reuses the same root-page fetch a human tester does first: look at the
obvious headers (Server, X-Powered-By) and a handful of body-content
signatures for widely-deployed CMSes/frameworks. This is deliberately
not a full Wappalyzer-style ruleset -- a dozen high-confidence, low-noise
signatures that cover the common cases a coursework-scale target is
likely to run, rather than hundreds of brittle regexes.

Output is informational (what's running), not a vulnerability on its
own -- the correlate agent's CVE lookup is what turns a detected
product/version into a risk; this tool is nmap's web-layer counterpart,
covering what a port scan can't see from inside an HTTP response.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .http_tool import scoped_request

HEADER_FINGERPRINTS = ("server", "x-powered-by")

# (signature substring in page body, human-readable label). Checked in
# order; all matches are kept, not just the first.
BODY_SIGNATURES = (
    ("wp-content", "WordPress"),
    ("Drupal.settings", "Drupal"),
    ("/sites/default/files", "Drupal"),
    ("Joomla!", "Joomla"),
    ("content=\"Joomla", "Joomla"),
    ("csrfmiddlewaretoken", "Django"),
    ("laravel_session", "Laravel"),
    ("__NEXT_DATA__", "Next.js"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("Shopify.shop", "Shopify"),
)


@dataclass
class TechFingerprintResult:
    checked_url: str
    header_hints: dict[str, str] = field(default_factory=dict)
    body_matches: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def run_tech_fingerprint(config: RunConfig, evidence: EvidenceLogger) -> TechFingerprintResult:
    started = time.time()
    evidence.log("TOOL_CALL", tool="tech_fingerprint", target=config.target_origin)

    res = scoped_request(config, evidence, method="GET", path="/")

    header_hints: dict[str, str] = {}
    for key, value in (res.headers or {}).items():
        if key.lower() in HEADER_FINGERPRINTS and value:
            header_hints[key] = value

    body = res.body_excerpt or ""
    body_matches = sorted({label for needle, label in BODY_SIGNATURES if needle in body})

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="tech_fingerprint",
        header_hints=header_hints,
        body_matches=body_matches,
        duration_s=duration,
    )

    return TechFingerprintResult(
        checked_url=res.url,
        header_hints=header_hints,
        body_matches=body_matches,
        duration_s=duration,
    )
