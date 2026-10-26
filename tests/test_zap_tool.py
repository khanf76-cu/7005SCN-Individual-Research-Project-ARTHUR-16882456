from unittest.mock import MagicMock, patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.zap_tool import run_zap


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _response(json_data, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


def test_zap_runs_spider_then_active_scan_and_collects_alerts(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    call_log = []

    def fake_get(url, params=None, timeout=None):
        endpoint = url.split("8098", 1)[1]
        call_log.append(endpoint)
        if endpoint == "/JSON/core/view/version/":
            return _response({"version": "2.15.0"})
        if endpoint == "/JSON/core/action/accessUrl/":
            return _response({"Result": "OK"})
        if endpoint == "/JSON/spider/action/scan/":
            return _response({"scan": "0"})
        if endpoint == "/JSON/spider/view/status/":
            return _response({"status": "100"})
        if endpoint == "/JSON/ascan/action/scan/":
            return _response({"scan": "0"})
        if endpoint == "/JSON/ascan/view/status/":
            return _response({"status": "100"})
        if endpoint == "/JSON/core/view/alerts/":
            return _response({
                "alerts": [
                    {
                        "alert": "SQL Injection", "risk": "High", "confidence": "High",
                        "url": "http://10.15.20.21:3001/user", "param": "id",
                        "description": "SQLi found", "solution": "Use parameterised queries",
                        "cweid": "89",
                    }
                ]
            })
        if endpoint == "/JSON/core/action/shutdown/":
            return _response({"Result": "OK"})
        raise AssertionError(f"unexpected ZAP API call: {endpoint}")

    mock_proc = MagicMock()
    mock_proc.wait.return_value = 0

    with patch("agent.tools.zap_tool.zap_available", return_value=True), \
         patch("agent.tools.zap_tool.subprocess.Popen", return_value=mock_proc), \
         patch("agent.tools.zap_tool.requests.get", side_effect=fake_get):
        result = run_zap(cfg, evidence, max_scan_time_s=30)

    assert result.error is None
    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.risk == "high"
    assert alert.param == "id"
    assert alert.cwe_id == "89"
    assert "/JSON/core/action/shutdown/" in call_log  # daemon must always be told to shut down


def test_zap_ascan_400_still_returns_spider_phase_alerts(tmp_path):
    """Regression test: against a CDN-fronted or otherwise unusual target,
    the spider can legitimately crawl zero pages, leaving the target out of
    ZAP's Sites tree -- at which point `ascan/action/scan` returns a real
    HTTP 400 even though the target itself is fine. That must not wipe out
    the whole run: accessUrl should still have seeded the tree, and
    whatever the passive scanner already found should still be reported."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    import requests as requests_module

    call_log = []

    def fake_get(url, params=None, timeout=None):
        endpoint = url.split("8098", 1)[1]
        call_log.append(endpoint)
        if endpoint == "/JSON/core/view/version/":
            return _response({"version": "2.15.0"})
        if endpoint == "/JSON/core/action/accessUrl/":
            return _response({"Result": "OK"})
        if endpoint == "/JSON/spider/action/scan/":
            return _response({"scan": "0"})
        if endpoint == "/JSON/spider/view/status/":
            return _response({"status": "100"})
        if endpoint == "/JSON/ascan/action/scan/":
            resp = MagicMock()
            resp.status_code = 400
            http_error = requests_module.HTTPError("400 Client Error: Bad Request")
            resp.raise_for_status.side_effect = http_error
            return resp
        if endpoint == "/JSON/core/view/alerts/":
            return _response({
                "alerts": [
                    {
                        "alert": "Missing Anti-clickjacking Header", "risk": "Medium", "confidence": "Medium",
                        "url": "http://10.15.20.21:3001/", "param": None,
                        "description": "X-Frame-Options not set", "solution": "Set X-Frame-Options",
                        "cweid": "1021",
                    }
                ]
            })
        if endpoint == "/JSON/core/action/shutdown/":
            return _response({"Result": "OK"})
        raise AssertionError(f"unexpected ZAP API call: {endpoint}")

    mock_proc = MagicMock()
    mock_proc.wait.return_value = 0

    with patch("agent.tools.zap_tool.zap_available", return_value=True), \
         patch("agent.tools.zap_tool.subprocess.Popen", return_value=mock_proc), \
         patch("agent.tools.zap_tool.requests.get", side_effect=fake_get):
        result = run_zap(cfg, evidence, max_scan_time_s=30)

    assert result.error is None  # the ascan 400 is absorbed, not surfaced as a hard failure
    assert result.truncated is True  # but honestly reflects that active scanning didn't complete
    assert len(result.alerts) == 1  # spider/passive-phase alerts are still returned
    assert result.alerts[0].name == "Missing Anti-clickjacking Header"
    assert "/JSON/core/action/shutdown/" in call_log


def test_zap_reports_error_and_still_shuts_down_if_daemon_never_becomes_ready(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    import requests as requests_module

    mock_proc = MagicMock()
    mock_proc.wait.return_value = 0

    with patch("agent.tools.zap_tool.zap_available", return_value=True), \
         patch("agent.tools.zap_tool.subprocess.Popen", return_value=mock_proc), \
         patch("agent.tools.zap_tool.requests.get", side_effect=requests_module.ConnectionError("refused")), \
         patch("agent.tools.zap_tool.STARTUP_TIMEOUT_S", 0), \
         patch("agent.tools.zap_tool.POLL_INTERVAL_S", 0):
        result = run_zap(cfg, evidence, max_scan_time_s=10)

    assert result.error is not None
    assert "did not become ready" in result.error
    assert result.alerts == []
