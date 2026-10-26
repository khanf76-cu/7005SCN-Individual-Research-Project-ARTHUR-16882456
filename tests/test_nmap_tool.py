from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.nikto_tool import ScopeViolation
from agent.tools.nmap_tool import run_nmap

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="3001">
        <state state="open"/>
        <service name="http" product="Node.js" version="20.3.0"/>
        <cpe>cpe:/a:nodejs:node.js:20.3.0</cpe>
        <script id="http-stored-xss" output="VULNERABLE: Possible stored XSS in CVE-2023-99999"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_nmap_blocks_host_outside_scope(tmp_path: Path):
    cfg = RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.99",),  # mismatched
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)
    with patch("agent.tools.nmap_tool.nmap_available", return_value=True):
        with pytest.raises(ScopeViolation):
            run_nmap(cfg, evidence)


def test_nmap_parses_xml_into_services_and_script_hits(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_subprocess_run(cmd, **kwargs):
        # The real run_nmap passes -oX <path>; find it and write our fixture XML there.
        oX_index = cmd.index("-oX")
        out_path = Path(cmd[oX_index + 1])
        out_path.write_text(SAMPLE_NMAP_XML)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("agent.tools.nmap_tool.nmap_available", return_value=True), \
         patch("agent.tools.nmap_tool.subprocess.run", side_effect=fake_subprocess_run):
        result = run_nmap(cfg, evidence)

    assert len(result.services) == 1  # only the open port
    svc = result.services[0]
    assert svc.port == 3001
    assert svc.product == "Node.js"
    assert svc.version == "20.3.0"
    assert "cpe:/a:nodejs:node.js:20.3.0" in svc.cpe

    assert len(result.script_hits) == 1
    assert result.script_hits[0].script_id == "http-stored-xss"
    assert "CVE-2023-99999" in result.script_hits[0].output


def test_nmap_raises_when_binary_missing(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)
    with patch("agent.tools.nmap_tool.nmap_available", return_value=False):
        with pytest.raises(RuntimeError):
            run_nmap(cfg, evidence)
