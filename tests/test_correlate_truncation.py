"""Regression tests for the correlate-agent input truncation defect.

Previously the findings JSON was hard-sliced at 12,000 characters. On a
run where ZAP produced 521 alerts, everything after the first ~12k chars
(i.e. nearly all ZAP output) was silently dropped and the JSON handed to
the model was cut mid-object. Every finding must now reach the model.
"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent.agents.correlate_agent import compact_findings, run_correlate_agent
from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.findings import Finding


def _zap(title, severity, url):
    return Finding(
        source_agent="va", title=title, category="http_vuln", severity=severity,
        confidence="suspected", endpoint=url, evidence=f"zap: {title} at {url}",
        extra={"tool": "zap"},
    )


def _many_findings():
    out = [
        Finding(source_agent="recon", title="Discoverable path: /ftp", category="exposed_path",
                severity="medium", confidence="confirmed", endpoint="/ftp", evidence="HTTP 200 on /ftp"),
    ]
    for i in range(94):
        out.append(_zap("Cross-Domain Misconfiguration", "medium", f"https://t/a{i}"))
        out.append(_zap("Strict-Transport-Security Header Not Set", "low", f"https://t/b{i}"))
        out.append(_zap("Timestamp Disclosure - Unix", "low", f"https://t/c{i}"))
    for i in range(76):
        out.append(_zap("Content Security Policy (CSP) Header Not Set", "medium", f"https://t/d{i}"))
    return out


RAW_COUNT = 1 + 94 * 3 + 76


def test_compact_findings_groups_without_losing_anything():
    groups = compact_findings(_many_findings())
    assert len(groups) == 5
    assert sum(g["occurrences"] for g in groups) == RAW_COUNT
    csp = next(g for g in groups if g["title"].startswith("Content Security Policy"))
    assert csp["occurrences"] == 76
    assert len(csp["endpoints"]) == 76  # every endpoint kept
    assert groups[0]["severity"] == "medium"
    assert groups[-1]["severity"] == "low"


def test_correlate_agent_sends_every_finding_as_valid_json(tmp_path: Path):
    cfg = RunConfig(
        target_origin="http://10.15.20.21:3001", allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key", openai_model="gpt-5-mini", rag_enabled=False,
    )
    evidence = EvidenceLogger(run_id="trunc-run", out_dir=tmp_path)
    reply = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
            "executive_summary": "x", "overall_risk_rating": "medium",
            "findings": [], "deduplication_notes": ""})))],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
    )
    with patch("agent.agents.correlate_agent.OpenAI") as mock_openai:
        mock_openai.return_value.chat.completions.create.return_value = reply
        result = run_correlate_agent(cfg, evidence, recon_findings=[], nmap_findings=[],
                                     va_findings=_many_findings())

    sent = mock_openai.return_value.chat.completions.create.call_args.kwargs["messages"][1]["content"]
    block = sent.split("endpoints):\n", 1)[1].split("\n\nLIVE CVE DATA", 1)[0]
    parsed = json.loads(block)  # well-formed, never sliced mid-object
    assert sum(g["occurrences"] for g in parsed) == RAW_COUNT
    assert "https://t/c93" in block  # the very last ZAP alert reaches the model
    assert result.raw_input_finding_count == RAW_COUNT
    assert result.grouped_finding_count == 5
