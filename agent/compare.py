"""Build a RAG-off vs RAG-on comparison table from two or more run results.

Each run's AgentRunResult (saved as JSON by the CLI) plus its ScoreResult
(if a ground-truth register was supplied) are combined into one table,
mirroring the kind of comparison your proposal's evaluation metrics
section asked for: detection rate, requests/tool-calls, timing, token
cost, RAG retrieval count, and false positive rate side by side.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path


def load_run(run_result_path: Path) -> dict:
    return json.loads(run_result_path.read_text())


def summarise_group(runs: list[dict], score_results: list[dict] | None = None) -> dict:
    """Aggregate a list of same-condition runs (e.g. all RAG-off repeats)
    into mean/min/max, the way your proposal's three-repeat E2/E3 design
    intended to characterise run-to-run variation."""
    if not runs:
        return {}

    def stat(key: str) -> dict:
        values = [r[key] for r in runs if r.get(key) is not None]
        if not values:
            return {"mean": None, "min": None, "max": None, "n": 0}
        return {
            "mean": statistics.mean(values),
            "min": min(values),
            "max": max(values),
            "n": len(values),
        }

    summary = {
        "n_runs": len(runs),
        "terminal_statuses": [r.get("terminal_status") for r in runs],
        "duration_s": stat("duration_s"),
        "model_calls": stat("model_calls"),
        "tool_calls": stat("tool_calls"),
        "input_tokens": stat("input_tokens"),
        "output_tokens": stat("output_tokens"),
        "rag_retrievals": stat("rag_retrievals"),
        "confirmed_finding_count": {
            "mean": statistics.mean([len(r.get("findings", [])) for r in runs]),
        },
    }

    if score_results:
        detection_rates = [
            s["detection_rate"] for s in score_results if s.get("detection_rate") is not None
        ]
        fp_rates = [
            s["false_positive_rate"] for s in score_results if s.get("false_positive_rate") is not None
        ]
        summary["detection_rate"] = {
            "mean": statistics.mean(detection_rates) if detection_rates else None,
            "n": len(detection_rates),
        }
        summary["false_positive_rate"] = {
            "mean": statistics.mean(fp_rates) if fp_rates else None,
            "n": len(fp_rates),
        }

    return summary


def render_markdown_table(rag_off_summary: dict, rag_on_summary: dict) -> str:
    def fmt(group: dict, key: str, subkey: str = "mean", digits: int = 2) -> str:
        val = group.get(key, {})
        if isinstance(val, dict):
            v = val.get(subkey)
        else:
            v = val
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return f"{v:.{digits}f}"
        return str(v)

    rows = [
        ("Runs (n)", str(rag_off_summary.get("n_runs", 0)), str(rag_on_summary.get("n_runs", 0))),
        ("Mean duration (s)", fmt(rag_off_summary, "duration_s"), fmt(rag_on_summary, "duration_s")),
        ("Mean model calls", fmt(rag_off_summary, "model_calls"), fmt(rag_on_summary, "model_calls")),
        ("Mean tool calls", fmt(rag_off_summary, "tool_calls"), fmt(rag_on_summary, "tool_calls")),
        ("Mean input tokens", fmt(rag_off_summary, "input_tokens", digits=0), fmt(rag_on_summary, "input_tokens", digits=0)),
        ("Mean output tokens", fmt(rag_off_summary, "output_tokens", digits=0), fmt(rag_on_summary, "output_tokens", digits=0)),
        ("Mean RAG retrievals", fmt(rag_off_summary, "rag_retrievals"), fmt(rag_on_summary, "rag_retrievals")),
        ("Mean confirmed findings", fmt(rag_off_summary, "confirmed_finding_count"), fmt(rag_on_summary, "confirmed_finding_count")),
        ("Mean detection rate", fmt(rag_off_summary, "detection_rate"), fmt(rag_on_summary, "detection_rate")),
        ("Mean false positive rate", fmt(rag_off_summary, "false_positive_rate"), fmt(rag_on_summary, "false_positive_rate")),
    ]

    lines = ["| Metric | RAG OFF | RAG ON |", "|---|---:|---:|"]
    for name, off_val, on_val in rows:
        lines.append(f"| {name} | {off_val} | {on_val} |")
    return "\n".join(lines)
