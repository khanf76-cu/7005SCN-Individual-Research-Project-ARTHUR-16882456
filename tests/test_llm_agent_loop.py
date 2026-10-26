"""End-to-end test of the agent loop's orchestration logic, with the
OpenAI client and tool execution mocked out. This verifies the control
flow (tool call -> dispatch -> feed result back -> report_findings ends
the run) independently of having a live API key or target, which matters
because that control flow is the actual original contribution being
assessed.
"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent.config import RunConfig
from agent.llm_agent import run_agent


def make_config(rag_enabled=False):
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=rag_enabled,
        max_turns=5,
        max_tool_calls=10,
    )


def _tool_call(call_id, name, arguments: dict):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def _chat_response(tool_calls=None, content=None, finish_reason="stop"):
    message = MagicMock()
    message.tool_calls = tool_calls
    message.content = content
    message.model_dump.return_value = {
        "role": "assistant",
        "content": content,
        **({"tool_calls": [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in tool_calls
        ]} if tool_calls else {}),
    }
    choice = SimpleNamespace(message=message, finish_reason=finish_reason)
    usage = SimpleNamespace(prompt_tokens=100, completion_tokens=20)
    return SimpleNamespace(choices=[choice], usage=usage)


def test_agent_loop_calls_tool_then_reports_findings(tmp_path: Path):
    cfg = make_config()

    # Turn 1: model asks to run nikto.
    turn1 = _chat_response(tool_calls=[_tool_call("call_1", "run_nikto", {})])
    # Turn 2: model reports one confirmed finding and stops.
    turn2 = _chat_response(
        tool_calls=[
            _tool_call(
                "call_2",
                "report_findings",
                {
                    "findings": [
                        {
                            "title": "Stack trace disclosure",
                            "severity": "low",
                            "evidence": "GET /rest/products returned a stack trace",
                            "confidence": "confirmed",
                            "endpoint": "/rest/products",
                        }
                    ]
                },
            )
        ]
    )

    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = [turn1, turn2]

    fake_nikto_result = SimpleNamespace(
        returncode=0,
        findings=[],
        truncated=False,
    )

    with patch("agent.llm_agent.OpenAI", return_value=mock_client), \
         patch("agent.llm_agent.run_nikto", return_value=fake_nikto_result) as mock_nikto:
        result = run_agent(cfg, evidence_dir=tmp_path)

    assert result.terminal_status == "completed"
    assert len(result.findings) == 1
    assert result.findings[0]["confidence"] == "confirmed"
    assert result.tool_calls == 1
    assert result.model_calls == 2
    assert mock_nikto.called

    evidence_lines = (tmp_path / "evidence.jsonl").read_text().strip().splitlines()
    event_types = [json.loads(line)["event_type"] for line in evidence_lines]
    assert "RUN_START" in event_types
    assert "FINDINGS_REPORTED" in event_types
    assert "RUN_END" in event_types


def test_agent_loop_stops_at_turn_budget_without_report(tmp_path: Path):
    cfg = make_config()
    cfg = RunConfig(**{**cfg.__dict__, "max_turns": 2})

    # Model never calls report_findings and never calls a tool.
    stall_response = _chat_response(tool_calls=None, content="thinking...")

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = stall_response

    with patch("agent.llm_agent.OpenAI", return_value=mock_client):
        result = run_agent(cfg, evidence_dir=tmp_path)

    assert result.terminal_status == "turn_budget_exhausted"
    assert result.findings == []
    assert result.model_calls == 2


def test_agent_loop_with_rag_enabled_logs_retrievals(tmp_path: Path):
    cfg = make_config(rag_enabled=True)
    corpus_dir = Path(__file__).resolve().parent.parent / "corpus"

    turn1 = _chat_response(
        tool_calls=[
            _tool_call(
                "call_1",
                "report_findings",
                {"findings": []},
            )
        ]
    )

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = turn1

    with patch("agent.llm_agent.OpenAI", return_value=mock_client):
        result = run_agent(cfg, evidence_dir=tmp_path, corpus_dir=corpus_dir)

    assert result.rag_enabled is True
    manifest = json.loads((tmp_path / "run_manifest.json").read_text())
    assert manifest["rag_enabled"] is True
    assert manifest["rag_corpus_doc_count"] >= 4
