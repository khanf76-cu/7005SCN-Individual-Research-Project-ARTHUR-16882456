"""Recon agent: attack-surface mapping.

The first stage of the pipeline -- maps attack surface before the nmap
and VA agents probe anything in detail. Runs six scoped recon tools and
normalises all of their output into the shared Finding schema:

  1. dirbrute_tool          directory/path brute-force
  2. subdomain_tool         DNS-based subdomain enumeration
  3. robots_sitemap_tool    robots.txt Disallow leads + sitemap.xml URLs
  4. security_headers_tool  missing baseline security response headers
  5. http_methods_tool      OPTIONS probe for risky HTTP methods enabled
  6. tech_fingerprint_tool  header/body-based CMS/framework fingerprinting

Every one of these goes through the same scoped_request primitive
(http_tool.scoped_request), so every single request -- across all six
tools -- is still checked against RunConfig.is_in_scope() and logged to
evidence before it is sent.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..config import RunConfig
from ..evidence import EvidenceLogger
from ..findings import Finding
from ..tools.dirbrute_tool import run_dirbrute
from ..tools.http_methods_tool import run_http_methods_probe
from ..tools.robots_sitemap_tool import run_robots_sitemap_recon
from ..tools.security_headers_tool import SECURITY_HEADERS, run_security_headers_check
from ..tools.subdomain_tool import run_subdomain_enum
from ..tools.tech_fingerprint_tool import run_tech_fingerprint


@dataclass
class ReconAgentResult:
    findings: list[Finding] = field(default_factory=list)
    paths_tried: int = 0
    subdomains_applicable: bool = False
    subdomains_found: int = 0
    robots_found: bool = False
    disallowed_paths_found: int = 0
    sitemap_urls_found: int = 0
    missing_security_headers: int = 0
    risky_http_methods: list[str] = field(default_factory=list)
    tech_detected: list[str] = field(default_factory=list)
    duration_s: float = 0.0


def run_recon_agent(config: RunConfig, evidence: EvidenceLogger) -> ReconAgentResult:
    started = time.time()
    evidence.log("AGENT_START", agent="recon")

    dirbrute_result = run_dirbrute(config, evidence)
    subdomain_result = run_subdomain_enum(config, evidence)
    robots_result = run_robots_sitemap_recon(config, evidence)
    headers_result = run_security_headers_check(config, evidence)
    methods_result = run_http_methods_probe(config, evidence)
    tech_result = run_tech_fingerprint(config, evidence)

    findings: list[Finding] = []

    for hit in dirbrute_result.hits:
        severity = "medium" if hit.status_code in (200, 201, 204) else "info"
        findings.append(
            Finding(
                source_agent="recon",
                title=f"Discoverable path: {hit.path}",
                category="exposed_path",
                severity=severity,
                confidence="confirmed",
                endpoint=hit.path,
                evidence=f"HTTP {hit.status_code} on {hit.path} ({hit.note}); "
                f"body sha256={hit.body_sha256[:16]}...",
                extra={"status_code": hit.status_code, "elapsed_s": hit.elapsed_s},
            )
        )

    for sub in subdomain_result.hits:
        findings.append(
            Finding(
                source_agent="recon",
                title=f"Subdomain resolves: {sub.subdomain}",
                category="subdomain",
                severity="info",
                confidence="confirmed",
                endpoint=sub.subdomain,
                evidence=f"{sub.subdomain} resolves to {sub.resolved_ip}. "
                "NOTE: this is recon information only -- it is NOT automatically "
                "in scope for further testing without separate authorization.",
                extra={"resolved_ip": sub.resolved_ip},
            )
        )

    for path in robots_result.disallowed_paths:
        findings.append(
            Finding(
                source_agent="recon",
                title=f"robots.txt Disallow lead: {path}",
                category="recon_lead",
                severity="info",
                confidence="confirmed",
                endpoint=path,
                evidence="Listed as Disallow in robots.txt -- the operator "
                "deliberately hid this path from crawlers, which often makes "
                "it worth a closer manual look.",
            )
        )

    if robots_result.sitemap_found and robots_result.sitemap_urls:
        findings.append(
            Finding(
                source_agent="recon",
                title=f"sitemap.xml exposes {len(robots_result.sitemap_urls)} URL(s)",
                category="recon_lead",
                severity="info",
                confidence="confirmed",
                endpoint="/sitemap.xml",
                evidence="; ".join(robots_result.sitemap_urls[:10])
                + (" ..." if len(robots_result.sitemap_urls) > 10 else ""),
            )
        )

    for missing in headers_result.missing:
        findings.append(
            Finding(
                source_agent="recon",
                title=f"Missing security header: {missing}",
                category="security_header",
                severity="info",
                confidence="confirmed",
                endpoint=headers_result.checked_url,
                evidence=f"Response did not set {missing} ({SECURITY_HEADERS[missing]}).",
            )
        )

    if methods_result.risky_methods:
        findings.append(
            Finding(
                source_agent="recon",
                title="State-changing/debug HTTP method(s) enabled",
                category="http_methods",
                severity="medium",
                confidence="suspected",
                endpoint=methods_result.checked_url,
                evidence=f"OPTIONS reported Allow: {', '.join(methods_result.allowed_methods)} "
                f"-- includes {', '.join(methods_result.risky_methods)}, which should "
                "usually be disabled on a production endpoint.",
                extra={"allowed_methods": methods_result.allowed_methods},
            )
        )

    if tech_result.header_hints or tech_result.body_matches:
        detected_bits = list(tech_result.header_hints.values()) + tech_result.body_matches
        findings.append(
            Finding(
                source_agent="recon",
                title="Technology fingerprint",
                category="tech_fingerprint",
                severity="info",
                confidence="suspected",
                endpoint=tech_result.checked_url,
                evidence=f"Detected: {', '.join(detected_bits)}.",
                extra={
                    "header_hints": tech_result.header_hints,
                    "body_matches": tech_result.body_matches,
                },
            )
        )

    tech_detected = sorted(set(list(tech_result.header_hints.values()) + tech_result.body_matches))

    result = ReconAgentResult(
        findings=findings,
        paths_tried=dirbrute_result.paths_tried,
        subdomains_applicable=subdomain_result.applicable,
        subdomains_found=len(subdomain_result.hits),
        robots_found=robots_result.robots_found,
        disallowed_paths_found=len(robots_result.disallowed_paths),
        sitemap_urls_found=len(robots_result.sitemap_urls),
        missing_security_headers=len(headers_result.missing),
        risky_http_methods=methods_result.risky_methods,
        tech_detected=tech_detected,
        duration_s=time.time() - started,
    )
    evidence.log(
        "AGENT_END",
        agent="recon",
        finding_count=len(findings),
        duration_s=result.duration_s,
    )
    return result
