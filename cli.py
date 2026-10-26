#!/usr/bin/env python3
"""CLI entrypoint for the LLM pentest agent artefact.

Usage:
    python cli.py run --rag off --out runs/e2-r1
    python cli.py run --rag on  --out runs/e3-r1
    python cli.py score --run runs/e2-r1 --ground-truth ground_truth.csv
    python cli.py compare --off-dir runs/rag-off --on-dir runs/rag-on
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from agent.compare import render_markdown_table, summarise_group
from agent.config import load_config
from agent.llm_agent import run_agent
from agent.scorer import load_findings, load_ground_truth, score_run

HERE = Path(__file__).resolve().parent


def cmd_run(args: argparse.Namespace) -> None:
    config = load_config(rag_override=(args.rag == "on"))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Starting run {config.run_id} against {config.target_origin} "
          f"(RAG {'ON' if config.rag_enabled else 'OFF'})")

    result = run_agent(
        config,
        evidence_dir=out_dir,
        corpus_dir=(HERE / "corpus") if config.rag_enabled else None,
    )

    result_path = out_dir / "run_result.json"
    result_path.write_text(json.dumps(asdict(result), indent=2))
    findings_path = out_dir / "findings.json"
    findings_path.write_text(json.dumps(result.findings, indent=2))

    print(f"[+] Run finished: status={result.terminal_status} "
          f"findings={len(result.findings)} tool_calls={result.tool_calls} "
          f"model_calls={result.model_calls} duration={result.duration_s:.1f}s")
    print(f"[+] Evidence: {out_dir / 'evidence.jsonl'}")
    print(f"[+] Result:   {result_path}")


def cmd_score(args: argparse.Namespace) -> None:
    cases = load_ground_truth(Path(args.ground_truth))
    findings = load_findings(Path(args.run) / "findings.json")
    score = score_run(cases, findings)
    out_path = Path(args.run) / "score.json"
    out_path.write_text(json.dumps(score.to_dict(), indent=2))
    print(json.dumps(score.to_dict(), indent=2))
    print(f"\n[+] Score written to {out_path}")


def cmd_compare(args: argparse.Namespace) -> None:
    off_runs = _load_group(Path(args.off_dir))
    on_runs = _load_group(Path(args.on_dir))

    off_scores = _load_group_scores(Path(args.off_dir))
    on_scores = _load_group_scores(Path(args.on_dir))

    off_summary = summarise_group(off_runs, off_scores)
    on_summary = summarise_group(on_runs, on_scores)

    table = render_markdown_table(off_summary, on_summary)
    print(table)

    out_path = Path(args.off_dir).parent / "comparison.md"
    out_path.write_text("# RAG OFF vs RAG ON comparison\n\n" + table + "\n")
    print(f"\n[+] Written to {out_path}")


def _load_group(dir_path: Path) -> list[dict]:
    runs = []
    for run_dir in sorted(dir_path.glob("*")):
        rf = run_dir / "run_result.json"
        if rf.exists():
            runs.append(json.loads(rf.read_text()))
    return runs


def _load_group_scores(dir_path: Path) -> list[dict]:
    scores = []
    for run_dir in sorted(dir_path.glob("*")):
        sf = run_dir / "score.json"
        if sf.exists():
            scores.append(json.loads(sf.read_text()))
    return scores


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run one agent assessment")
    p_run.add_argument("--rag", choices=["on", "off"], default="off")
    p_run.add_argument("--out", required=True, help="Output directory for this run's evidence")
    p_run.set_defaults(func=cmd_run)

    p_score = sub.add_parser("score", help="Score one run against a ground-truth register")
    p_score.add_argument("--run", required=True, help="Run output directory (from `run`)")
    p_score.add_argument("--ground-truth", required=True, help="Path to ground_truth.csv")
    p_score.set_defaults(func=cmd_score)

    p_compare = sub.add_parser("compare", help="Compare a RAG-off group vs RAG-on group")
    p_compare.add_argument("--off-dir", required=True, help="Directory containing RAG-off run subdirectories")
    p_compare.add_argument("--on-dir", required=True, help="Directory containing RAG-on run subdirectories")
    p_compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code not in (0, None):
            print(f"[!] {e}", file=sys.stderr)
        raise
