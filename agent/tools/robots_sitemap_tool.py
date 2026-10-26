"""robots.txt / sitemap.xml recon.

Two of the oldest recon tricks in the book, and still some of the
highest-signal: a `Disallow:` entry in robots.txt is a site operator
pointing a crawler (and, incidentally, a pentester) straight at a path
they considered sensitive enough to hide from search engines; a
sitemap.xml is a map of every URL the operator wants indexed. Both are
fetched exactly like any other in-scope path, through the same
scoped_request primitive.

Disallowed paths are reported as recon leads (info severity), not
auto-tested -- same philosophy as subdomain_tool: discovering a path
here doesn't put it in scope for deeper probing beyond what the other
recon/VA tools already try on their own.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..config import RunConfig
from ..evidence import EvidenceLogger
from .http_tool import scoped_request

DISALLOW_RE = re.compile(r"^\s*Disallow:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
MAX_ENTRIES = 50  # keep the report and the LLM context manageable


@dataclass
class RobotsSitemapResult:
    robots_found: bool = False
    disallowed_paths: list[str] = field(default_factory=list)
    sitemap_found: bool = False
    sitemap_urls: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def run_robots_sitemap_recon(config: RunConfig, evidence: EvidenceLogger) -> RobotsSitemapResult:
    started = time.time()
    evidence.log("TOOL_CALL", tool="robots_sitemap", target=config.target_origin)

    robots_res = scoped_request(config, evidence, method="GET", path="/robots.txt")
    robots_found = robots_res.status_code == 200
    disallowed: list[str] = []
    if robots_found:
        disallowed = DISALLOW_RE.findall(robots_res.body_excerpt)[:MAX_ENTRIES]
        disallowed = [p for p in disallowed if p not in ("", "/")]

    sitemap_res = scoped_request(config, evidence, method="GET", path="/sitemap.xml")
    sitemap_found = sitemap_res.status_code == 200
    sitemap_urls: list[str] = []
    if sitemap_found:
        target_host = urlparse(config.target_origin).netloc
        for loc in SITEMAP_LOC_RE.findall(sitemap_res.body_excerpt)[: MAX_ENTRIES * 2]:
            # Only keep in-scope URLs; a sitemap can legally list
            # off-host CDN/asset URLs we have no business reporting on.
            if urlparse(loc).netloc in ("", target_host):
                sitemap_urls.append(loc)
            if len(sitemap_urls) >= MAX_ENTRIES:
                break

    duration = time.time() - started
    evidence.log(
        "TOOL_RESULT",
        tool="robots_sitemap",
        robots_found=robots_found,
        disallowed_count=len(disallowed),
        sitemap_found=sitemap_found,
        sitemap_url_count=len(sitemap_urls),
        duration_s=duration,
    )

    return RobotsSitemapResult(
        robots_found=robots_found,
        disallowed_paths=disallowed,
        sitemap_found=sitemap_found,
        sitemap_urls=sitemap_urls,
        duration_s=duration,
    )
