from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.dirbrute_tool import DirBruteHit, run_dirbrute
from agent.tools.http_tool import HttpResult


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_dirbrute_flags_paths_differing_from_baseline(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nftp\nnotreal\n")

    def fake_scoped_request(config, ev, *, method, path, headers=None, data=None):
        if "__definitely-not-a-real-path-xyz123__" in path:
            return HttpResult("GET", path, 404, 0.01, "not found", "baseline-hash")
        if path == "/admin":
            return HttpResult("GET", path, 200, 0.02, "admin panel", "admin-hash")
        if path == "/ftp":
            return HttpResult("GET", path, 404, 0.01, "not found", "baseline-hash")
        return HttpResult("GET", path, 404, 0.01, "not found", "baseline-hash")

    with patch("agent.tools.dirbrute_tool.scoped_request", side_effect=fake_scoped_request):
        result = run_dirbrute(cfg, evidence, wordlist_path=wordlist, delay_s=0)

    paths_found = [h.path for h in result.hits]
    assert "/admin" in paths_found
    assert "/ftp" not in paths_found  # matches baseline 404 -> not a real hit
    assert result.paths_tried == 3


def test_dirbrute_evidence_logged(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n")

    with patch(
        "agent.tools.dirbrute_tool.scoped_request",
        return_value=HttpResult("GET", "/admin", 404, 0.01, "x", "h"),
    ):
        run_dirbrute(cfg, evidence, wordlist_path=wordlist, delay_s=0)

    log_lines = evidence.evidence_path.read_text().strip().splitlines()
    event_types = [__import__("json").loads(line)["event_type"] for line in log_lines]
    assert "TOOL_CALL" in event_types
    assert "TOOL_RESULT" in event_types
