import subprocess
from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.sqlmap_tool import run_sqlmap


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001/user?id=1",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _fake_completed_process(returncode=0):
    return subprocess.CompletedProcess(args=["sqlmap"], returncode=returncode, stdout="", stderr="")


def test_sqlmap_parses_results_csv(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        out_dir = Path(cmd[cmd.index("--output-dir") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results-10262026_0831pm.csv").write_text(
            "Target URL,Place,Parameter,Technique(s),Note(s)\n"
            "http://10.15.20.21:3001/user?id=1,GET,id,BTU,\n"
        )
        return _fake_completed_process()

    with patch("agent.tools.sqlmap_tool.sqlmap_available", return_value=True), \
         patch("agent.tools.sqlmap_tool.subprocess.run", side_effect=fake_run):
        result = run_sqlmap(cfg, evidence)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.parameter == "id"
    assert f.place == "GET"
    assert f.techniques == "BTU"
    assert result.error is None


def test_sqlmap_no_findings_when_nothing_crawlable(tmp_path: Path):
    """When sqlmap's crawl finds no links/params, it writes no results
    file at all -- that's a legitimate "nothing testable" outcome, not
    an error."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    with patch("agent.tools.sqlmap_tool.sqlmap_available", return_value=True), \
         patch("agent.tools.sqlmap_tool.subprocess.run", return_value=_fake_completed_process()):
        result = run_sqlmap(cfg, evidence)

    assert result.findings == []
    assert result.error is None


def test_sqlmap_handles_timeout(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=180)

    with patch("agent.tools.sqlmap_tool.sqlmap_available", return_value=True), \
         patch("agent.tools.sqlmap_tool.subprocess.run", side_effect=fake_run):
        result = run_sqlmap(cfg, evidence)

    assert result.truncated is True
    assert result.error == "sqlmap timed out"
