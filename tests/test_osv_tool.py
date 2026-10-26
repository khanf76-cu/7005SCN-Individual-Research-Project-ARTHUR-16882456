import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.osv_tool import run_osv_check


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


SAMPLE_OSV_JSON = {
    "results": [
        {
            "source": {"path": "/tmp/package-lock.json"},
            "packages": [
                {
                    "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype pollution",
                         "database_specific": {"severity": "HIGH"}}
                    ],
                }
            ],
        }
    ]
}


def test_osv_check_finds_nothing_when_no_manifest_exposed(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    not_found_resp = MagicMock(status_code=404, content=b"")

    with patch("agent.tools.osv_tool.osv_scanner_available", return_value=True), \
         patch("agent.tools.osv_tool.requests.get", return_value=not_found_resp):
        result = run_osv_check(cfg, evidence)

    assert result.manifests_found == []
    assert result.vulnerabilities == []
    assert result.error is None


def test_osv_check_scans_exposed_manifest_and_parses_vulnerabilities(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="t", out_dir=tmp_path)

    def fake_get(url, **kwargs):
        if url.endswith("package-lock.json"):
            return MagicMock(status_code=200, content=b'{"name": "fake"}')
        return MagicMock(status_code=404, content=b"")

    def fake_run(cmd, **kwargs):
        report_path = Path(cmd[cmd.index("--output") + 1])
        report_path.write_text(json.dumps(SAMPLE_OSV_JSON))
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")  # osv-scanner exits 1 when vulns found

    with patch("agent.tools.osv_tool.osv_scanner_available", return_value=True), \
         patch("agent.tools.osv_tool.requests.get", side_effect=fake_get), \
         patch("agent.tools.osv_tool.subprocess.run", side_effect=fake_run):
        result = run_osv_check(cfg, evidence)

    assert result.manifests_found == ["package-lock.json"]
    assert len(result.vulnerabilities) == 1
    v = result.vulnerabilities[0]
    assert v.package_name == "lodash"
    assert v.vuln_id == "GHSA-p6mc-m468-83gw"
    assert v.severity == "HIGH"
