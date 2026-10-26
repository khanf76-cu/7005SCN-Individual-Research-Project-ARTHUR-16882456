from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.http_tool import scoped_request
from agent.tools.nikto_tool import ScopeViolation


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_scoped_request_builds_url_against_configured_origin(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = b"ok"

    with patch("agent.tools.http_tool.requests.request", return_value=fake_response) as mock_req:
        result_ok = scoped_request(cfg, evidence, method="GET", path="/rest/products")

    assert result_ok.url == "http://10.15.20.21:3001/rest/products"
    assert result_ok.status_code == 200
    mock_req.assert_called_once()


def test_scope_violation_raised_for_tampered_origin(tmp_path: Path):
    cfg = RunConfig(
        target_origin="http://attacker.example.com",
        allowed_hosts=("10.15.20.21",),  # mismatched on purpose
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)
    with pytest.raises(ScopeViolation):
        scoped_request(cfg, evidence, method="GET", path="/")


def test_evidence_logged_for_every_request_attempt(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake_response = MagicMock()
    fake_response.status_code = 404
    fake_response.content = b"not found"

    with patch("agent.tools.http_tool.requests.request", return_value=fake_response):
        scoped_request(cfg, evidence, method="GET", path="/nonexistent-path-xyz")

    log_lines = evidence.evidence_path.read_text().strip().splitlines()
    event_types = [__import__("json").loads(line)["event_type"] for line in log_lines]
    assert "TOOL_CALL" in event_types
    assert "TOOL_RESULT" in event_types
