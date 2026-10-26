"""The agent loop: LLM decides actions, tools execute, LLM interprets.

This is the original orchestration logic for the artefact. It is a plain
tool-calling loop against the OpenAI Chat Completions API (no external
agent framework), so every decision point is visible and explainable:

    1. Build the system prompt (+ RAG context if enabled for this run).
    2. Ask the model for the next action (a tool call or a finding report).
    3. Execute the tool call through the scoped wrappers.
    4. Feed the result back, and repeat until the model reports findings
       or a turn/tool-call budget is hit.

Every model call and tool call is logged via EvidenceLogger so a run can
be reconstructed and scored after the fact.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from openai import OpenAI

from .config import RunConfig, resolve_pinned_address
from .evidence import EvidenceLogger
from .rag import RagCorpus
from .tools.http_tool import scoped_request
from .tools.nikto_tool import ScopeViolation, run_nikto

SYSTEM_PROMPT = """You are an authorized penetration testing assistant \
operating ONLY against the single pre-approved target origin given to you. \
You must never attempt to contact any other host, and you must never \
fabricate a finding you did not actually observe through a tool call.

You have exactly two tools:
- run_nikto(tuning: optional string) -- runs the nikto vulnerability \
scanner against the target.
- http_request(method, path, headers?, data?) -- sends one scoped HTTP \
request to the target and returns status, timing, and a body excerpt.

Work iteratively: run nikto first for broad coverage, then use \
http_request to follow up on and verify specific findings (e.g. \
confirm a stack trace is actually present in the body, not just that \
the endpoint returned an error status). Only report a finding as \
CONFIRMED if you have direct evidence (an actual response body \
excerpt, status code, or nikto hit) for it. If a response is blocked, \
rejected (4xx from a filter), or inconclusive, say so -- do not \
upgrade it to a confirmed vulnerability.

When you are done investigating (or have reached a reasonable stopping \
point), call the `report_findings` function with a list of findings, \
each with: title, severity (info/low/medium/high/critical), evidence \
(what you actually observed), and confidence (confirmed/suspected).
"""

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "run_nikto",
            "description": "Run the nikto vulnerability scanner against the authorized target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tuning": {
                        "type": "string",
                        "description": "Optional nikto -Tuning value to focus the scan, e.g. '9' for SQL injection checks.",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send one scoped HTTP request to the authorized target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "HEAD", "PUT", "DELETE"]},
                    "path": {"type": "string", "description": "Path relative to the target origin, e.g. '/rest/products'."},
                    "headers": {"type": "object"},
                    "data": {"type": "string"},
                },
                "required": ["method", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_findings",
            "description": "Report final findings and end the assessment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                                "evidence": {"type": "string"},
                                "confidence": {"type": "string", "enum": ["confirmed", "suspected"]},
                                "endpoint": {"type": "string"},
                            },
                            "required": ["title", "severity", "evidence", "confidence"],
                        },
                    }
                },
                "required": ["findings"],
            },
        },
    },
]


@dataclass
class AgentRunResult:
    run_id: str
    rag_enabled: bool
    findings: list[dict] = field(default_factory=list)
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    rag_retrievals: int = 0
    duration_s: float = 0.0
    terminal_status: str = "completed"


def run_agent(
    config: RunConfig,
    evidence_dir: Path,
    *,
    corpus_dir: Path | None = None,
) -> AgentRunResult:
    evidence = EvidenceLogger(run_id=config.run_id, out_dir=evidence_dir)
    client = OpenAI(api_key=config.openai_api_key)

    corpus: RagCorpus | None = None
    if config.rag_enabled:
        if corpus_dir is None:
            raise ValueError("rag_enabled is True but no corpus_dir was given")
        corpus = RagCorpus(corpus_dir)

    pinned_ip = resolve_pinned_address(
        config.allowed_hosts[0]
    )

    evidence.write_manifest(
        {
            "run_id": config.run_id,
            "target_origin": config.target_origin,
            "allowed_hosts": list(config.allowed_hosts),
            "dns_pinned_address": pinned_ip,
            "rag_enabled": config.rag_enabled,
            "rag_corpus_doc_count": corpus.document_count if corpus else 0,
            "model": config.openai_model,
            "max_turns": config.max_turns,
            "created_at_utc": time.time(),
        }
    )
    evidence.log("RUN_START", config=config.target_origin, rag_enabled=config.rag_enabled)

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.append(
        {
            "role": "user",
            "content": f"Authorized target origin: {config.target_origin}\n"
            "Begin the assessment.",
        }
    )

    result = AgentRunResult(run_id=config.run_id, rag_enabled=config.rag_enabled)
    started = time.time()
    turn = 0

    while turn < config.max_turns:
        turn += 1

        # --- RAG step: retrieve context relevant to the latest turn ---
        if corpus is not None:
            query = _latest_context_query(messages)
            retrieved = corpus.retrieve(query, k=3)
            if retrieved:
                result.rag_retrievals += len(retrieved)
                context_block = "\n\n".join(
                    f"[RAG:{d.doc_id} score={d.score:.3f}]\n{d.text}" for d in retrieved
                )
                evidence.log(
                    "RAG_RETRIEVAL",
                    query=query,
                    retrieved_doc_ids=[d.doc_id for d in retrieved],
                    scores=[d.score for d in retrieved],
                )
                messages.append(
                    {
                        "role": "system",
                        "content": "Relevant reference material (retrieved, may or may not apply):\n"
                        + context_block,
                    }
                )

        evidence.log("MODEL_CALL", turn=turn, message_count=len(messages))
        response = client.chat.completions.create(
            model=config.openai_model,
            messages=messages,
            tools=TOOLS_SCHEMA,
            tool_choice="auto",
        )
        result.model_calls += 1
        usage = response.usage
        if usage:
            result.input_tokens += usage.prompt_tokens
            result.output_tokens += usage.completion_tokens

        choice = response.choices[0]
        msg = choice.message
        messages.append(msg.model_dump(exclude_none=True))

        evidence.log(
            "MODEL_RESPONSE",
            turn=turn,
            finish_reason=choice.finish_reason,
            has_tool_calls=bool(msg.tool_calls),
            content_preview=(msg.content or "")[:300],
        )

        if not msg.tool_calls:
            # Model stopped without calling report_findings -- nudge once,
            # then stop to avoid an unbounded loop.
            messages.append(
                {
                    "role": "user",
                    "content": "Continue investigating with a tool call, or call "
                    "report_findings if you are done.",
                }
            )
            continue

        for tool_call in msg.tool_calls:
            if result.tool_calls >= config.max_tool_calls:
                result.terminal_status = "tool_call_budget_exhausted"
                break

            name = tool_call.function.name
            try:
                args = json.loads(tool_call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}

            if name == "report_findings":
                result.findings = args.get("findings", [])
                evidence.log("FINDINGS_REPORTED", findings=result.findings)
                result.duration_s = time.time() - started
                result.terminal_status = "completed"
                evidence.log("RUN_END", status=result.terminal_status)
                return result

            tool_result = _dispatch_tool(name, args, config, evidence)
            result.tool_calls += 1

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(tool_result, default=str)[:6000],
                }
            )

        if result.terminal_status == "tool_call_budget_exhausted":
            break

    result.duration_s = time.time() - started
    if result.terminal_status == "completed" and not result.findings:
        result.terminal_status = "turn_budget_exhausted"
    evidence.log("RUN_END", status=result.terminal_status)
    return result


def _latest_context_query(messages: list[dict]) -> str:
    for m in reversed(messages):
        if m.get("role") in ("tool", "assistant") and m.get("content"):
            content = m["content"]
            if isinstance(content, str):
                return content[:500]
    return "web application penetration testing"


def _dispatch_tool(name: str, args: dict, config: RunConfig, evidence: EvidenceLogger) -> dict:
    try:
        if name == "run_nikto":
            res = run_nikto(config, evidence, tuning=args.get("tuning"))
            return {
                "returncode": res.returncode,
                "finding_count": len(res.findings),
                "findings": [f.__dict__ for f in res.findings[:20]],
                "truncated": res.truncated,
            }
        if name == "http_request":
            res = scoped_request(
                config,
                evidence,
                method=args.get("method", "GET"),
                path=args.get("path", "/"),
                headers=args.get("headers"),
                data=args.get("data"),
            )
            return {
                "status_code": res.status_code,
                "elapsed_s": res.elapsed_s,
                "body_excerpt": res.body_excerpt,
                "body_sha256": res.body_sha256,
                "error": res.error,
            }
        return {"error": f"unknown tool {name!r}"}
    except ScopeViolation as exc:
        evidence.log("SCOPE_VIOLATION_BLOCKED", tool=name, args=args, reason=str(exc))
        return {"error": f"blocked: {exc}"}
