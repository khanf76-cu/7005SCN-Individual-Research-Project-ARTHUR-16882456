from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.http_methods_tool import run_http_methods_probe
from agent.tools.http_tool import HttpResult


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_flags_risky_methods(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake = HttpResult(
        "OPTIONS", "http://10.15.20.21:3001/", 200, 0.01, "", "h",
        headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"},
    )
    with patch("agent.tools.http_methods_tool.scoped_request", return_value=fake):
        result = run_http_methods_probe(cfg, evidence)

    assert set(result.allowed_methods) == {"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    assert set(result.risky_methods) == {"PUT", "DELETE"}


def test_no_allow_header_is_empty_not_an_error(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake = HttpResult("OPTIONS", "http://10.15.20.21:3001/", 404, 0.01, "", "h")
    with patch("agent.tools.http_methods_tool.scoped_request", return_value=fake):
        result = run_http_methods_probe(cfg, evidence)

    assert result.allowed_methods == []
    assert result.risky_methods == []
