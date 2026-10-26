from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.http_tool import HttpResult
from agent.tools.robots_sitemap_tool import run_robots_sitemap_recon

ROBOTS_BODY = """User-agent: *
Disallow: /admin
Disallow: /internal/api
Disallow: /
"""

SITEMAP_BODY = """<?xml version="1.0"?>
<urlset>
  <url><loc>http://10.15.20.21:3001/products</loc></url>
  <url><loc>http://10.15.20.21:3001/about</loc></url>
  <url><loc>http://evil-other-host.example/ignored</loc></url>
</urlset>
"""


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_parses_disallowed_paths_and_sitemap_urls(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_scoped_request(config, ev, *, method, path, headers=None, data=None):
        if path == "/robots.txt":
            return HttpResult("GET", path, 200, 0.01, ROBOTS_BODY, "h1")
        if path == "/sitemap.xml":
            return HttpResult("GET", path, 200, 0.01, SITEMAP_BODY, "h2")
        return HttpResult("GET", path, 404, 0.01, "", "h3")

    with patch("agent.tools.robots_sitemap_tool.scoped_request", side_effect=fake_scoped_request):
        result = run_robots_sitemap_recon(cfg, evidence)

    assert result.robots_found is True
    assert "/admin" in result.disallowed_paths
    assert "/internal/api" in result.disallowed_paths
    assert "/" not in result.disallowed_paths  # bare "/" filtered as noise

    assert result.sitemap_found is True
    assert "http://10.15.20.21:3001/products" in result.sitemap_urls
    assert "http://10.15.20.21:3001/about" in result.sitemap_urls
    assert "http://evil-other-host.example/ignored" not in result.sitemap_urls


def test_missing_robots_and_sitemap_reported_as_not_found(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    with patch(
        "agent.tools.robots_sitemap_tool.scoped_request",
        return_value=HttpResult("GET", "/x", 404, 0.01, "", "h"),
    ):
        result = run_robots_sitemap_recon(cfg, evidence)

    assert result.robots_found is False
    assert result.disallowed_paths == []
    assert result.sitemap_found is False
    assert result.sitemap_urls == []
