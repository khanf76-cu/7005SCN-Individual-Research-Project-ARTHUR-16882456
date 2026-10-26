from pathlib import Path
from unittest.mock import patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.agents.nmap_agent import run_nmap_agent
from agent.tools.nmap_tool import NmapResult, NmapScriptHit, NmapService


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def test_nmap_agent_raises_script_hit_severity_on_cve_mention(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    fake_result = NmapResult(
        target_host="10.15.20.21",
        services=[NmapService(3001, "tcp", "open", "http", "Node.js", "20.3.0", ["cpe:/a:nodejs:node.js"])],
        script_hits=[
            NmapScriptHit(port=3001, script_id="http-vuln-cve2023", output="VULNERABLE: CVE-2023-99999 found"),
            NmapScriptHit(port=3001, script_id="http-headers", output="no issues"),
        ],
    )

    with patch("agent.agents.nmap_agent.run_nmap", return_value=fake_result):
        result = run_nmap_agent(cfg, evidence)

    severities = {f.title: f.severity for f in result.findings}
    confidences = {f.title: f.confidence for f in result.findings}

    assert severities["NSE script result: http-vuln-cve2023"] == "high"
    assert confidences["NSE script result: http-vuln-cve2023"] == "confirmed"
    assert severities["NSE script result: http-headers"] == "info"
    assert confidences["NSE script result: http-headers"] == "suspected"
    assert result.open_ports == 1

    service_finding = next(f for f in result.findings if f.category == "service_version")
    assert service_finding.extra["product"] == "Node.js"
    assert service_finding.extra["version"] == "20.3.0"
