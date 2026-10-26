"""Integration test for the recon agent's wiring: all six sub-tools are
called and their output is turned into the shared Finding schema.
Every sub-tool is mocked at its import point in recon_agent, so this
test exercises only the agent's own normalisation logic -- the
sub-tools themselves are tested independently in their own test files.
"""
from pathlib import Path
from unittest.mock import patch

from agent.agents.recon_agent import run_recon_agent
from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.dirbrute_tool import DirBruteHit, DirBruteResult
from agent.tools.http_methods_tool import HttpMethodsResult
from agent.tools.robots_sitemap_tool import RobotsSitemapResult
from agent.tools.security_headers_tool import SecurityHeadersResult
from agent.tools.subdomain_tool import SubdomainHit, SubdomainResult
from agent.tools.tech_fingerprint_tool import TechFingerprintResult


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_recon_agent_aggregates_all_six_tools(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    dirbrute_result = DirBruteResult(
        target=cfg.target_origin,
        hits=[DirBruteHit(path="/admin", status_code=200, elapsed_s=0.01, body_sha256="h")],
        paths_tried=42,
    )
    subdomain_result = SubdomainResult(
        base_domain=None, applicable=False, skip_reason="literal IP target", hits=[]
    )
    robots_result = RobotsSitemapResult(
        robots_found=True,
        disallowed_paths=["/internal"],
        sitemap_found=True,
        sitemap_urls=["http://10.15.20.21:3001/products"],
    )
    headers_result = SecurityHeadersResult(
        checked_url=cfg.target_origin + "/",
        present=["x-frame-options"],
        missing=["strict-transport-security", "content-security-policy"],
    )
    methods_result = HttpMethodsResult(
        checked_url=cfg.target_origin + "/",
        allowed_methods=["GET", "PUT", "DELETE"],
        risky_methods=["PUT", "DELETE"],
    )
    tech_result = TechFingerprintResult(
        checked_url=cfg.target_origin + "/",
        header_hints={"Server": "nginx"},
        body_matches=["React"],
    )

    with patch("agent.agents.recon_agent.run_dirbrute", return_value=dirbrute_result), \
         patch("agent.agents.recon_agent.run_subdomain_enum", return_value=subdomain_result), \
         patch("agent.agents.recon_agent.run_robots_sitemap_recon", return_value=robots_result), \
         patch("agent.agents.recon_agent.run_security_headers_check", return_value=headers_result), \
         patch("agent.agents.recon_agent.run_http_methods_probe", return_value=methods_result), \
         patch("agent.agents.recon_agent.run_tech_fingerprint", return_value=tech_result):
        result = run_recon_agent(cfg, evidence)

    # counts surfaced on the result object (used by the web UI's live view)
    assert result.paths_tried == 42
    assert result.disallowed_paths_found == 1
    assert result.sitemap_urls_found == 1
    assert result.missing_security_headers == 2
    assert result.risky_http_methods == ["PUT", "DELETE"]
    assert "React" in result.tech_detected

    # findings: one per dirbrute hit, one robots lead, one sitemap summary,
    # two missing-header findings, one risky-methods finding, one tech finding
    categories = [f.category for f in result.findings]
    assert categories.count("exposed_path") == 1
    assert categories.count("recon_lead") == 2  # robots lead + sitemap summary
    assert categories.count("security_header") == 2
    assert categories.count("http_methods") == 1
    assert categories.count("tech_fingerprint") == 1
    assert all(f.source_agent == "recon" for f in result.findings)


def test_recon_agent_handles_quiet_target_gracefully(tmp_path: Path):
    """Nothing found anywhere -- the agent should still return cleanly
    with empty lists/zero counts, not crash or emit noise findings."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    empty_dirbrute = DirBruteResult(target=cfg.target_origin, hits=[], paths_tried=10)
    empty_subdomain = SubdomainResult(base_domain=None, applicable=False, skip_reason="x", hits=[])
    empty_robots = RobotsSitemapResult()
    empty_headers = SecurityHeadersResult(checked_url=cfg.target_origin + "/", present=list(
        ["strict-transport-security", "x-content-type-options", "x-frame-options",
         "content-security-policy", "referrer-policy"]
    ), missing=[])
    empty_methods = HttpMethodsResult(checked_url=cfg.target_origin + "/")
    empty_tech = TechFingerprintResult(checked_url=cfg.target_origin + "/")

    with patch("agent.agents.recon_agent.run_dirbrute", return_value=empty_dirbrute), \
         patch("agent.agents.recon_agent.run_subdomain_enum", return_value=empty_subdomain), \
         patch("agent.agents.recon_agent.run_robots_sitemap_recon", return_value=empty_robots), \
         patch("agent.agents.recon_agent.run_security_headers_check", return_value=empty_headers), \
         patch("agent.agents.recon_agent.run_http_methods_probe", return_value=empty_methods), \
         patch("agent.agents.recon_agent.run_tech_fingerprint", return_value=empty_tech):
        result = run_recon_agent(cfg, evidence)

    assert result.findings == []
    assert result.missing_security_headers == 0
    assert result.risky_http_methods == []
    assert result.tech_detected == []
