from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.http_tool import HttpResult
from agent.tools.tech_fingerprint_tool import run_tech_fingerprint


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_detects_header_and_body_signatures(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake = HttpResult(
        "GET", "http://10.15.20.21:3001/", 200, 0.01,
        '<html><body><div data-reactroot="">hi, I load /wp-content/themes/x.css</div></body></html>',
        "h",
        headers={"Server": "nginx/1.18.0", "X-Powered-By": "Express"},
    )
    with patch("agent.tools.tech_fingerprint_tool.scoped_request", return_value=fake):
        result = run_tech_fingerprint(cfg, evidence)

    assert result.header_hints == {"Server": "nginx/1.18.0", "X-Powered-By": "Express"}
    assert "WordPress" in result.body_matches
    assert "React" in result.body_matches


def test_no_signatures_found_is_empty_not_an_error(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake = HttpResult("GET", "http://10.15.20.21:3001/", 200, 0.01, "<html>plain</html>", "h")
    with patch("agent.tools.tech_fingerprint_tool.scoped_request", return_value=fake):
        result = run_tech_fingerprint(cfg, evidence)

    assert result.header_hints == {}
    assert result.body_matches == []
