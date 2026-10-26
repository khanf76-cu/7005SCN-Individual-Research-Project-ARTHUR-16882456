from unittest.mock import MagicMock, patch

import requests

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.cookie_tool import run_cookie_check


def make_config():
    return RunConfig(
        target_origin="https://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _fake_cookie(name, secure=False, httponly=False, samesite=None):
    c = MagicMock()
    c.name = name
    c.secure = secure
    c.has_nonstandard_attr.side_effect = lambda attr: attr == "HttpOnly" and httponly
    c.get_nonstandard_attr.side_effect = lambda attr: samesite if attr == "SameSite" else None
    return c


def test_cookie_check_flags_missing_attributes_on_https(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    resp = MagicMock()
    resp.cookies = [_fake_cookie("session", secure=False, httponly=False, samesite=None)]

    with patch("agent.tools.cookie_tool.requests.get", return_value=resp):
        result = run_cookie_check(cfg, evidence)

    attrs = {i.missing_attribute for i in result.issues}
    assert attrs == {"Secure", "HttpOnly", "SameSite"}
    assert result.cookies_found == 1


def test_cookie_check_no_issues_when_all_attributes_set(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    resp = MagicMock()
    resp.cookies = [_fake_cookie("secure_flag", secure=True, httponly=True, samesite="Strict")]

    with patch("agent.tools.cookie_tool.requests.get", return_value=resp):
        result = run_cookie_check(cfg, evidence)

    assert result.issues == []


def test_cookie_check_does_not_flag_secure_over_plain_http(tmp_path):
    cfg = RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    resp = MagicMock()
    resp.cookies = [_fake_cookie("session", secure=False, httponly=True, samesite="Strict")]

    with patch("agent.tools.cookie_tool.requests.get", return_value=resp):
        result = run_cookie_check(cfg, evidence)

    assert result.issues == []  # Secure attribute is meaningless/not expected over plain http


def test_cookie_check_retries_once_on_transient_connection_failure(tmp_path):
    """Regression test: ARTHUR runs 8 VA sub-tools concurrently against
    the same target, which can transiently saturate a small/local target
    just enough to refuse one connection attempt without actually being
    down. A single failure must not be reported as a hard tool error if
    a retry succeeds."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    resp = MagicMock()
    resp.cookies = [_fake_cookie("session", secure=True, httponly=True, samesite="Strict")]

    with patch(
        "agent.tools.cookie_tool.requests.get",
        side_effect=[requests.exceptions.ConnectTimeout("connect timeout=15"), resp],
    ), patch("agent.tools.cookie_tool.time.sleep"):
        result = run_cookie_check(cfg, evidence)

    assert result.error is None
    assert result.cookies_found == 1
    assert result.issues == []


def test_cookie_check_still_fails_cleanly_when_target_is_actually_unreachable(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    with patch(
        "agent.tools.cookie_tool.requests.get",
        side_effect=requests.exceptions.ConnectTimeout("connect timeout=15"),
    ), patch("agent.tools.cookie_tool.time.sleep"):
        result = run_cookie_check(cfg, evidence)

    assert result.error is not None
    assert result.cookies_found == 0
