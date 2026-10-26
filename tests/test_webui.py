"""Smoke tests for the Flask web UI: routes register, pages render, and
exports (JSON/HTML/PDF) produce well-formed output. Uses a directly
injected job in the in-memory store rather than running a real
assessment, so these run with no API key, nikto, nmap, or target.
"""
import json
import sys
from pathlib import Path

import pytest

WEBUI_DIR = Path(__file__).resolve().parent.parent / "webui"
sys.path.insert(0, str(WEBUI_DIR))

import app as webapp  # noqa: E402


@pytest.fixture
def client():
    webapp.app.config["TESTING"] = True
    return webapp.app.test_client()


SAMPLE_RESULT = {
    "run_id": "run-test",
    "target_origin": "http://10.15.20.21:3001",
    "duration_s": 42.5,
    "errors": {},
    "correlate": {
        "executive_summary": "Test summary of findings.",
        "overall_risk_rating": "medium",
        "deduplication_notes": "Merged nikto and dirbrute hits on /ftp/.",
        "findings": [
            {
                "title": "Stack trace disclosure",
                "severity": "high",
                "confidence": "confirmed",
                "endpoint": "/rest/products",
                "evidence": "GET returned a stack trace",
                "category": "information_disclosure",
                "source_agents": ["va", "nmap"],
                "related_cves": ["CVE-2021-12345"],
            },
            {
                "title": "Open FTP listing",
                "severity": "medium",
                "confidence": "confirmed",
                "endpoint": "/ftp/",
                "evidence": "Directory listing exposed",
                "category": "exposed_path",
                "source_agents": ["recon"],
                "related_cves": [],
            },
        ],
    },
}


def _inject_completed_job(job_id: str, write_file: bool = True) -> None:
    webapp.JOBS[job_id] = {
        "status": "completed",
        "target_input": SAMPLE_RESULT["target_origin"],
        "target_origin": SAMPLE_RESULT["target_origin"],
        "stages": {"recon": "completed", "nmap": "completed", "va": "completed", "correlate": "completed"},
        "error": None,
        "result": SAMPLE_RESULT,
    }
    if write_file:
        out_dir = webapp.RUNS_DIR / job_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "final_report.json").write_text(json.dumps(SAMPLE_RESULT))


def test_index_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"ARTHUR" in r.data
    assert b"Target" in r.data
    assert b"authorized" in r.data.lower()


def test_scan_requires_target(client):
    r = client.post("/scan", data={"target": "", "authorized": "on"})
    assert r.status_code == 400


def test_scan_requires_authorization_checkbox(client):
    r = client.post("/scan", data={"target": "example.com"})  # no authorized field
    assert r.status_code == 400
    assert b"authoriz" in r.data.lower()


def test_health_page_renders(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert b"System Health" in r.data
    assert b"Python version" in r.data


def test_health_api_returns_json(client):
    r = client.get("/api/health?network=0")
    assert r.status_code == 200
    data = r.get_json()
    assert "overall_status" in data
    assert isinstance(data["checks"], list)
    assert len(data["checks"]) > 0
    assert not any(c["name"] == "NVD API reachability" for c in data["checks"])


def test_results_page_renders_completed_job(client):
    _inject_completed_job("job-a", write_file=False)
    r = client.get("/results/job-a")
    assert r.status_code == 200
    assert b"Stack trace disclosure" in r.data
    assert b"CVE-2021-12345" in r.data
    # severity ordering: high should appear before medium in the table
    high_pos = r.data.find(b"Stack trace disclosure")
    medium_pos = r.data.find(b"Open FTP listing")
    assert high_pos < medium_pos


def test_results_page_unknown_job(client):
    r = client.get("/results/does-not-exist")
    assert r.status_code == 404


def test_status_endpoint(client):
    _inject_completed_job("job-b", write_file=False)
    r = client.get("/status/job-b")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "completed"
    assert data["has_result"] is True


def test_export_json(client):
    _inject_completed_job("job-c")
    r = client.get("/export/job-c/json")
    assert r.status_code == 200
    body = json.loads(r.data)
    assert body["correlate"]["overall_risk_rating"] == "medium"


def test_export_html_standalone(client):
    _inject_completed_job("job-d")
    r = client.get("/export/job-d/html")
    assert r.status_code == 200
    assert b"Stack trace disclosure" in r.data
    assert b"<html" in r.data.lower()


def test_export_pdf_is_valid_pdf(client):
    _inject_completed_job("job-e")
    r = client.get("/export/job-e/pdf")
    assert r.status_code == 200
    assert r.data[:4] == b"%PDF"


def test_export_without_result_returns_404(client):
    webapp.JOBS["job-pending"] = {
        "status": "running",
        "target_origin": "http://x",
        "stages": {},
        "error": None,
        "result": None,
    }
    r = client.get("/export/job-pending/pdf")
    assert r.status_code == 404
