import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.wapiti_tool import run_wapiti

SAMPLE_REPORT = {
    "vulnerabilities": {
        "SQL Injection": [
            {
                "method": "GET", "path": "/user", "info": "SQL Injection via injection in the parameter id",
                "level": 4, "parameter": "id", "module": "sql", "http_request": "GET /user?id=1",
            }
        ],
        "Reflected Cross Site Scripting": [],
    },
    "anomalies": {},
    "additionals": {},
}


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _fake_completed_process(returncode=0):
    return subprocess.CompletedProcess(args=["wapiti"], returncode=returncode, stdout="", stderr="")


def test_wapiti_parses_vulnerabilities_section(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(json.dumps(SAMPLE_REPORT))
        return _fake_completed_process()

    with patch("agent.tools.wapiti_tool.wapiti_available", return_value=True), \
         patch("agent.tools.wapiti_tool.subprocess.run", side_effect=fake_run):
        result = run_wapiti(cfg, evidence)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "SQL Injection"
    assert f.parameter == "id"
    assert f.module == "sql"
    assert result.error is None


def test_wapiti_seeds_crawler_with_in_scope_start_urls_only(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    captured_cmd = {}

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(json.dumps({"vulnerabilities": {}, "anomalies": {}, "additionals": {}}))
        return _fake_completed_process()

    with patch("agent.tools.wapiti_tool.wapiti_available", return_value=True), \
         patch("agent.tools.wapiti_tool.subprocess.run", side_effect=fake_run):
        run_wapiti(
            cfg, evidence,
            extra_start_urls=["http://10.15.20.21:3001/user?id=1", "http://evil.example.com/"],
        )

    cmd = captured_cmd["cmd"]
    assert "http://10.15.20.21:3001/user?id=1" in cmd
    assert "http://evil.example.com/" not in cmd  # out of scope -- must be dropped, not passed to wapiti


def test_wapiti_surfaces_error_when_report_missing_and_nonzero_exit(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    with patch("agent.tools.wapiti_tool.wapiti_available", return_value=True), \
         patch("agent.tools.wapiti_tool.subprocess.run", return_value=_fake_completed_process(returncode=1)):
        result = run_wapiti(cfg, evidence)

    assert result.findings == []
    assert result.error is not None
