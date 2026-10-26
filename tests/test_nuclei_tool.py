import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.nuclei_tool import run_nuclei


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _fake_completed_process(returncode=0):
    return subprocess.CompletedProcess(args=["nuclei"], returncode=returncode, stdout="", stderr="")


def test_nuclei_parses_jsonl_output(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    line1 = json.dumps({
        "template-id": "exposed-panel",
        "info": {"name": "Admin Panel Exposed", "severity": "medium", "description": "An admin panel is exposed",
                  "classification": {"cve-id": []}},
        "matched-at": "http://10.15.20.21:3001/admin",
    })
    line2 = json.dumps({
        "template-id": "CVE-2021-1234",
        "info": {"name": "Some CVE", "severity": "critical", "description": "desc",
                  "classification": {"cve-id": ["CVE-2021-1234"]}},
        "matched-at": "http://10.15.20.21:3001/",
    })

    def fake_run(cmd, **kwargs):
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(line1 + "\n" + line2 + "\n")
        return _fake_completed_process()

    with patch("agent.tools.nuclei_tool.nuclei_available", return_value=True), \
         patch("agent.tools.nuclei_tool.subprocess.run", side_effect=fake_run):
        result = run_nuclei(cfg, evidence)

    assert len(result.findings) == 2
    critical = next(f for f in result.findings if f.severity == "critical")
    assert critical.cve_ids == ["CVE-2021-1234"]


def test_nuclei_no_findings_when_nothing_matches(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text("")  # nuclei creates an empty file when nothing matches
        return _fake_completed_process()

    with patch("agent.tools.nuclei_tool.nuclei_available", return_value=True), \
         patch("agent.tools.nuclei_tool.subprocess.run", side_effect=fake_run):
        result = run_nuclei(cfg, evidence)

    assert result.findings == []
    assert result.error is None


def test_nuclei_handles_timeout_but_keeps_partial_results(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    partial_line = json.dumps({
        "template-id": "found-before-timeout",
        "info": {"name": "Found before timeout", "severity": "low", "description": "", "classification": {}},
        "matched-at": "http://10.15.20.21:3001/",
    })

    def fake_run(cmd, **kwargs):
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(partial_line + "\n")
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=180)

    with patch("agent.tools.nuclei_tool.nuclei_available", return_value=True), \
         patch("agent.tools.nuclei_tool.subprocess.run", side_effect=fake_run):
        result = run_nuclei(cfg, evidence)

    assert result.truncated is True
    assert result.error == "nuclei timed out"
    assert len(result.findings) == 1  # partial results written before the timeout are still kept
