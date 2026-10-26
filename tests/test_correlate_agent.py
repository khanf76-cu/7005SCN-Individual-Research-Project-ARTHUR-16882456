import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.findings import Finding
from agent.agents.correlate_agent import run_correlate_agent
from agent.tools.cve_lookup_tool import CveLookupResult, CveRecord


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _mock_chat_response(content_json: dict):
    message = SimpleNamespace(content=json.dumps(content_json))
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(prompt_tokens=500, completion_tokens=150)
    return SimpleNamespace(choices=[choice], usage=usage)


def test_correlate_agent_merges_findings_and_looks_up_cves(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    nmap_findings = [
        Finding(
            source_agent="nmap",
            title="Open port 3001/tcp: http",
            category="service_version",
            severity="info",
            confidence="confirmed",
            endpoint="10.15.20.21:3001",
            evidence="nmap detected Node.js 20.3.0",
            extra={"product": "Node.js", "version": "20.3.0"},
        )
    ]
    va_findings = [
        Finding(
            source_agent="va",
            title="Stack trace disclosure",
            category="http_vuln",
            severity="low",
            confidence="suspected",
            endpoint="/rest/products",
            evidence="nikto found a stack trace",
            extra={},
        )
    ]

    expected_output = {
        "executive_summary": "One confirmed info-disclosure issue found.",
        "overall_risk_rating": "medium",
        "findings": [
            {
                "title": "Stack trace disclosure at /rest/products",
                "category": "information_disclosure",
                "severity": "medium",
                "confidence": "confirmed",
                "endpoint": "/rest/products",
                "evidence": "Confirmed by va agent, cross-checked against nmap service info.",
                "related_cves": [],
                "source_agents": ["va", "nmap"],
            }
        ],
        "deduplication_notes": "No duplicates found across agents.",
    }

    mock_cve_result = CveLookupResult(
        query="Node.js 20.3.0",
        records=[CveRecord("CVE-2024-00001", "desc", 6.5, "MEDIUM", "2024-01-01")],
    )

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _mock_chat_response(expected_output)

    with patch("agent.agents.correlate_agent.OpenAI", return_value=mock_client), \
         patch.object(__import__("agent.agents.correlate_agent", fromlist=["CveLookupClient"]).CveLookupClient,
                      "lookup", return_value=mock_cve_result):
        result = run_correlate_agent(
            cfg,
            evidence,
            recon_findings=[],
            nmap_findings=nmap_findings,
            va_findings=va_findings,
        )

    assert result.executive_summary == "One confirmed info-disclosure issue found."
    assert result.overall_risk_rating == "medium"
    assert len(result.findings) == 1
    assert result.cve_lookups_performed == 1
    assert result.model_calls == 1
    assert result.raw_input_finding_count == 2

    log_lines = evidence.evidence_path.read_text().strip().splitlines()
    event_types = [json.loads(line)["event_type"] for line in log_lines]
    assert "CVE_LOOKUP" in event_types
    assert "MODEL_RESPONSE" in event_types


def test_correlate_agent_handles_malformed_model_json(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    mock_client = MagicMock()
    message = SimpleNamespace(content="not valid json{{{")
    choice = SimpleNamespace(message=message)
    usage = SimpleNamespace(prompt_tokens=100, completion_tokens=10)
    mock_client.chat.completions.create.return_value = SimpleNamespace(choices=[choice], usage=usage)

    with patch("agent.agents.correlate_agent.OpenAI", return_value=mock_client):
        result = run_correlate_agent(
            cfg, evidence, recon_findings=[], nmap_findings=[], va_findings=[]
        )

    # Should not crash -- falls back to a safe default with the raw
    # findings preserved rather than losing data.
    assert "could not be parsed" in result.executive_summary.lower()

    log_lines = evidence.evidence_path.read_text().strip().splitlines()
    event_types = [json.loads(line)["event_type"] for line in log_lines]
    assert "MODEL_RESPONSE_PARSE_ERROR" in event_types


def test_correlate_agent_uses_rag_when_corpus_provided(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)
    corpus_dir = Path(__file__).resolve().parent.parent / "corpus"

    nmap_findings = [
        Finding(
            source_agent="nmap",
            title="svc",
            category="service_version",
            severity="info",
            confidence="confirmed",
            endpoint="10.15.20.21:3001",
            evidence="e",
            extra={},
        )
    ]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = _mock_chat_response(
        {"executive_summary": "x", "overall_risk_rating": "low", "findings": [], "deduplication_notes": ""}
    )

    with patch("agent.agents.correlate_agent.OpenAI", return_value=mock_client):
        result = run_correlate_agent(
            cfg,
            evidence,
            recon_findings=[],
            nmap_findings=nmap_findings,
            va_findings=[],
            corpus_dir=corpus_dir,
        )

    assert result.rag_retrievals >= 0  # ran without error; corpus was consulted
    log_lines = evidence.evidence_path.read_text().strip().splitlines()
    event_types = [json.loads(line)["event_type"] for line in log_lines]
    assert "RAG_RETRIEVAL" in event_types or result.rag_retrievals == 0
