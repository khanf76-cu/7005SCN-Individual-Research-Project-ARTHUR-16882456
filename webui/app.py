#!/usr/bin/env python3
"""Black-cyan web UI for the multi-agent pentest artefact.

Accepts a target, runs the recon -> nmap -> va -> correlate pipeline in
a background thread, shows live-ish stage status, and renders/exports
the final correlated report as HTML, JSON, or PDF.

Run with: python webui/app.py
Then open http://127.0.0.1:5000/
"""
from __future__ import annotations

import json
import sys
import threading
import uuid
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(HERE))

from agent.config import InvalidTarget, build_config_for_target  # noqa: E402
from agent.health import run_health_checks  # noqa: E402
from agent.orchestrator import OrchestratorResult, run_full_assessment  # noqa: E402
from pdf_export import build_pdf_report  # noqa: E402

RUNS_DIR = PROJECT_ROOT / "webui_runs"
RUNS_DIR.mkdir(exist_ok=True)
CORPUS_DIR = PROJECT_ROOT / "corpus"

app = Flask(__name__)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@app.template_filter("severity_rank")
def severity_rank(severity: str | None) -> int:
    return _SEVERITY_RANK.get((severity or "info").lower(), 5)

# In-memory job store. Fine for a single-student, single-machine
# coursework tool; not intended for multi-user/production deployment.
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


def _set_stage(job_id: str, stage: str, status: str) -> None:
    with JOBS_LOCK:
        JOBS[job_id]["stages"][stage] = status


def _humanize_finding(f: dict) -> str:
    """One Finding dict -> one plain-English line for the live-results
    view, e.g. '[HIGH] Stack trace disclosure - /rest/products (GET
    returned a stack trace)'."""
    sev = (f.get("severity") or "info").upper()
    title = f.get("title") or "finding"
    endpoint = f.get("endpoint") or ""
    evidence = f.get("evidence") or ""
    line = f"[{sev}] {title}"
    if endpoint:
        line += f" - {endpoint}"
    if evidence:
        snippet = evidence if len(evidence) <= 160 else evidence[:157] + "..."
        line += f" ({snippet})"
    return line


def _humanize_stage(stage: str, data: dict) -> dict:
    """Turns one agent's raw result dict into a small human-readable
    summary (a one-line headline plus plain-English finding lines) for
    the web UI's live per-agent results panel -- shown the moment that
    agent finishes, independently of the other agents running
    alongside it."""
    findings = data.get("findings") or []

    if stage == "recon":
        headline = (
            f"{data.get('paths_tried', 0)} path(s) probed, "
            f"{data.get('subdomains_found', 0)} subdomain(s), "
            f"{data.get('disallowed_paths_found', 0)} robots.txt lead(s), "
            f"{data.get('missing_security_headers', 0)} missing header(s) "
            f"-- {len(findings)} finding(s)"
        )
    elif stage == "nmap":
        headline = f"{data.get('open_ports', 0)} open port(s) -- {len(findings)} finding(s)"
    elif stage == "va":
        tools_run = data.get("tools_run") or []
        tool_errors = data.get("tool_errors") or {}
        ok_count = max(len(tools_run) - len(tool_errors), 0)
        headline = f"{ok_count}/{len(tools_run)} VA tool(s) ran cleanly -- {len(findings)} finding(s)"
    elif stage == "correlate":
        headline = data.get("executive_summary") or f"{len(findings)} correlated finding(s)"
    else:
        headline = f"{len(findings)} finding(s)"

    lines = [_humanize_finding(f) for f in findings]
    if stage == "va":
        for tool_name, tool_error in (data.get("tool_errors") or {}).items():
            lines.append(f"[TOOL SKIPPED] {tool_name}: {tool_error}")

    return {
        "headline": headline,
        "lines": lines,
        "duration_s": data.get("duration_s"),
    }


def _run_job(job_id: str, target: str, rag_enabled: bool, skip_nmap: bool, api_key: str | None) -> None:
    try:
        config = build_config_for_target(
            target, rag_enabled=rag_enabled, api_key=api_key
        )
    except InvalidTarget as exc:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["error"] = str(exc)
        return

    out_dir = RUNS_DIR / job_id
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["run_id"] = config.run_id
        JOBS[job_id]["target_origin"] = config.target_origin

    def progress_callback(stage: str, status: str, result=None) -> None:
        _set_stage(job_id, stage, status)
        if result is not None:
            live_entry = _humanize_stage(stage, asdict(result))
            with JOBS_LOCK:
                JOBS[job_id]["live"][stage] = live_entry

    try:
        result = run_full_assessment(
            config,
            out_dir,
            corpus_dir=(CORPUS_DIR if rag_enabled else None),
            skip_nmap=skip_nmap,
            progress_callback=progress_callback,
        )
        result_dict = result.to_dict()
        (out_dir / "final_report.json").write_text(json.dumps(result_dict, indent=2, default=str))
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "completed"
            JOBS[job_id]["result"] = result_dict
    except Exception as exc:  # noqa: BLE001
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["error"] = str(exc)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    rag_enabled = request.form.get("rag_enabled") == "on"
    skip_nmap = request.form.get("skip_nmap") == "on"
    authorized = request.form.get("authorized") == "on"
    api_key = request.form.get("api_key", "").strip() or None

    if not target:
        return render_template("index.html", error="Target is required."), 400
    if not authorized:
        return render_template(
            "index.html",
            error="You must confirm you own or are authorized to test this target.",
        ), 400

    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "starting",
            "target_input": target,
            "stages": {"recon": "pending", "nmap": "pending", "va": "pending", "correlate": "pending"},
            "live": {},
            "result": None,
            "error": None,
        }

    thread = threading.Thread(
        target=_run_job, args=(job_id, target, rag_enabled, skip_nmap, api_key), daemon=True
    )
    thread.start()

    return redirect(url_for("show_results", job_id=job_id))


@app.route("/status/<job_id>")
def status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        return jsonify({"error": "unknown job_id"}), 404
    return jsonify(
        {
            "status": job["status"],
            "stages": job["stages"],
            "error": job.get("error"),
            "has_result": job.get("result") is not None,
            "live": job.get("live", {}),
        }
    )


def _annotate_severity_sort_key(job: dict) -> None:
    """Mutates job['result']['correlate']['findings'] in place, adding a
    numeric sort key so the results template can order by actual
    severity rank rather than alphabetically."""
    result = job.get("result")
    if not result:
        return
    correlate = result.get("correlate") or {}
    for f in correlate.get("findings", []):
        f["severity_sort_key"] = _SEVERITY_RANK.get((f.get("severity") or "info").lower(), 5)


@app.route("/results/<job_id>")
def show_results(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        return "Unknown job id", 404
    _annotate_severity_sort_key(job)
    return render_template("results.html", job_id=job_id, job=job)


@app.route("/export/<job_id>/json")
def export_json(job_id: str):
    path = RUNS_DIR / job_id / "final_report.json"
    if not path.exists():
        return "Report not ready", 404
    return send_file(path, as_attachment=True, download_name=f"arthur_report_{job_id}.json")


@app.route("/export/<job_id>/html")
def export_html(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None or job.get("result") is None:
        return "Report not ready", 404
    _annotate_severity_sort_key(job)
    html = render_template("report_standalone.html", job_id=job_id, job=job)
    out_path = RUNS_DIR / job_id / "report.html"
    out_path.write_text(html)
    return send_file(out_path, as_attachment=True, download_name=f"arthur_report_{job_id}.html")


@app.route("/export/<job_id>/pdf")
def export_pdf(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None or job.get("result") is None:
        return "Report not ready", 404

    out_path = RUNS_DIR / job_id / "report.pdf"
    build_pdf_report(job["result"], out_path)
    return send_file(out_path, as_attachment=True, download_name=f"arthur_report_{job_id}.pdf")


@app.route("/health")
def health_page():
    report = run_health_checks(check_network=True)
    return render_template("health.html", report=report)


@app.route("/api/health")
def health_api():
    check_network = request.args.get("network", "1") != "0"
    report = run_health_checks(check_network=check_network)
    return jsonify(report.to_dict())


if __name__ == "__main__":
    import os

    from dotenv import load_dotenv

    load_dotenv()  # so WEBUI_HOST/WEBUI_PORT in .env are picked up before app.run()

    # Binds to all interfaces by default (0.0.0.0), not just localhost --
    # this is meant to be reached from another machine's browser (e.g.
    # http://<this-server's-LAN-IP>:5000/), including when run as
    # arthur.service with no one at the console. There's no login on
    # this web UI, only the authorization checkbox on the scan form, so
    # don't expose port 5000 beyond a network you trust. Set
    # WEBUI_HOST=127.0.0.1 in .env to go back to localhost-only.
    host = os.environ.get("WEBUI_HOST", "0.0.0.0")
    port = int(os.environ.get("WEBUI_PORT", "5000"))
    print(f"ARTHUR web UI starting on http://{host}:{port}/")
    app.run(host=host, port=port, debug=False)
