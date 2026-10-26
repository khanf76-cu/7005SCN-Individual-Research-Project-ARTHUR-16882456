from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.http_tool import HttpResult
from agent.tools.security_headers_tool import run_security_headers_check


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_flags_missing_headers(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake = HttpResult(
        "GET", "http://10.15.20.21:3001/", 200, 0.01, "<html></html>", "h",
        headers={"Content-Type": "text/html"},
    )
    with patch("agent.tools.security_headers_tool.scoped_request", return_value=fake):
        result = run_security_headers_check(cfg, evidence)

    assert "strict-transport-security" in result.missing
    assert "x-frame-options" in result.missing
    assert result.present == []


def test_recognises_present_headers_case_insensitively(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake = HttpResult(
        "GET", "http://10.15.20.21:3001/", 200, 0.01, "<html></html>", "h",
        headers={"X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=1"},
    )
    with patch("agent.tools.security_headers_tool.scoped_request", return_value=fake):
        result = run_security_headers_check(cfg, evidence)

    assert "x-frame-options" in result.present
    assert "strict-transport-security" in result.present
    assert "content-security-policy" in result.missing
