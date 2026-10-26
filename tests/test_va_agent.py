from unittest.mock import patch

from agent.agents.va_agent import run_va_agent
from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.cookie_tool import CookieIssue, CookieResult
from agent.tools.nikto_tool import NiktoFinding, NiktoResult
from agent.tools.nuclei_tool import NucleiFinding, NucleiResult
from agent.tools.osv_tool import OsvResult, OsvVulnerability
from agent.tools.sqlmap_tool import SqlmapFinding, SqlmapResult
from agent.tools.tls_tool import TlsIssue, TlsResult
from agent.tools.wapiti_tool import WapitiFinding, WapitiResult
from agent.tools.zap_tool import ZapAlert, ZapResult


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _empty_nikto(target):
    return NiktoResult(target=target, findings=[], raw_stdout="", returncode=0, duration_s=0.1, truncated=False, error=None)


def _empty_tls(target):
    return TlsResult(target_host="10.15.20.21", target_port=3001, applicable=False, duration_s=0.01)


def _empty_cookies(target):
    return CookieResult(checked_url=target + "/", cookies_found=0, issues=[], duration_s=0.01)


def _empty_sqlmap(target):
    return SqlmapResult(target=target, findings=[], duration_s=0.1, truncated=False, error=None)


def _empty_wapiti(target):
    return WapitiResult(target=target, findings=[], duration_s=0.1, truncated=False, error=None)


def _patch_all_sub_tools(**overrides):
    """Returns a dict of {dotted-path: mock-or-callable} for every VA
    sub-tool, defaulting to "ran cleanly, found nothing" -- individual
    tests override only the one(s) they care about via `overrides`,
    keyed by short name (e.g. nikto=..., tls=...)."""
    cfg_target = "http://10.15.20.21:3001"
    defaults = {
        "agent.agents.va_agent.run_nikto": lambda *a, **k: overrides.get("nikto", _empty_nikto(cfg_target)),
        "agent.agents.va_agent.run_tls_check": lambda *a, **k: overrides.get("tls", _empty_tls(cfg_target)),
        "agent.agents.va_agent.run_cookie_check": lambda *a, **k: overrides.get("cookies", _empty_cookies(cfg_target)),
        "agent.agents.va_agent.run_sqlmap": lambda *a, **k: overrides.get("sqlmap", _empty_sqlmap(cfg_target)),
        "agent.agents.va_agent.run_wapiti": lambda *a, **k: overrides.get("wapiti", _empty_wapiti(cfg_target)),
        "agent.agents.va_agent.nuclei_available": lambda: "nuclei" in overrides,
        "agent.agents.va_agent.run_nuclei": lambda *a, **k: overrides.get(
            "nuclei", NucleiResult(target=cfg_target, findings=[], duration_s=0.1)
        ),
        "agent.agents.va_agent.osv_scanner_available": lambda: "osv" in overrides,
        "agent.agents.va_agent.run_osv_check": lambda *a, **k: overrides.get(
            "osv", OsvResult(target=cfg_target, manifests_checked=10, duration_s=0.1)
        ),
        "agent.agents.va_agent.zap_available": lambda: "zap" in overrides,
        "agent.agents.va_agent.run_zap": lambda *a, **k: overrides.get(
            "zap", ZapResult(target=cfg_target, alerts=[], duration_s=0.1)
        ),
    }
    return defaults


def test_va_agent_converts_nikto_findings_to_shared_schema(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    nikto_result = NiktoResult(
        target=cfg.target_origin,
        findings=[
            NiktoFinding(
                id="999976",
                osvdb="0",
                method="GET",
                url=cfg.target_origin + "/",
                message="The anti-clickjacking X-Frame-Options header is not present.",
            )
        ],
        raw_stdout="",
        returncode=0,
        duration_s=7.5,
        truncated=False,
        error=None,
    )

    patches = _patch_all_sub_tools(nikto=nikto_result)
    with patch.multiple("agent.agents.va_agent", **{k.rsplit(".", 1)[1]: v for k, v in patches.items()}):
        result = run_va_agent(cfg, evidence)

    nikto_findings = [f for f in result.findings if f.extra.get("tool") == "nikto"]
    assert len(nikto_findings) == 1
    f = nikto_findings[0]
    assert f.source_agent == "va"
    assert f.category == "http_vuln"
    assert f.confidence == "suspected"
    assert "X-Frame-Options" in f.evidence
    assert f.extra["osvdb"] == "0"
    assert "nikto" not in result.tool_errors


def test_va_agent_surfaces_tool_error_instead_of_hiding_it_as_zero_findings(tmp_path):
    """Regression test for the original bug report: a nikto invocation
    failure (wrong -Format, missing DTD, etc.) must come back as a
    visible tool_errors["nikto"], not just an empty, seemingly-clean
    findings list."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    nikto_result = NiktoResult(
        target=cfg.target_origin,
        findings=[],
        raw_stdout="+ ERROR: Invalid output format\n",
        returncode=0,
        duration_s=0.28,
        truncated=False,
        error="nikto reported an error: + ERROR: Invalid output format",
    )

    patches = _patch_all_sub_tools(nikto=nikto_result)
    with patch.multiple("agent.agents.va_agent", **{k.rsplit(".", 1)[1]: v for k, v in patches.items()}):
        result = run_va_agent(cfg, evidence)

    assert result.tool_errors["nikto"] == "nikto reported an error: + ERROR: Invalid output format"


def test_va_agent_high_signal_keyword_bumps_severity(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    nikto_result = NiktoResult(
        target=cfg.target_origin,
        findings=[
            NiktoFinding(
                id="1", osvdb=None, method="GET", url=cfg.target_origin + "/login",
                message="Possible SQL injection in parameter 'id'",
            )
        ],
        raw_stdout="", returncode=0, duration_s=1.0, truncated=False, error=None,
    )

    patches = _patch_all_sub_tools(nikto=nikto_result)
    with patch.multiple("agent.agents.va_agent", **{k.rsplit(".", 1)[1]: v for k, v in patches.items()}):
        result = run_va_agent(cfg, evidence)

    nikto_findings = [f for f in result.findings if f.extra.get("tool") == "nikto"]
    assert nikto_findings[0].severity == "high"


def test_va_agent_merges_findings_from_every_sub_tool(tmp_path):
    """All eight sub-tools run concurrently and their findings all land
    in one merged list, each tagged with which tool produced it."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    tls_result = TlsResult(
        target_host="10.15.20.21", target_port=3001, applicable=True,
        negotiated_protocol="TLSv1.3", duration_s=0.5,
        issues=[TlsIssue("self_signed", "Certificate is self-signed")],
    )
    cookie_result = CookieResult(
        checked_url=cfg.target_origin + "/", cookies_found=1, duration_s=0.1,
        issues=[CookieIssue("session", "HttpOnly", "Cookie 'session' lacks HttpOnly")],
    )
    sqlmap_result = SqlmapResult(
        target=cfg.target_origin, duration_s=5.0,
        findings=[SqlmapFinding(url=cfg.target_origin + "/user?id=1", place="GET", parameter="id", techniques="BTU", note="")],
    )
    wapiti_result = WapitiResult(
        target=cfg.target_origin, duration_s=3.0,
        findings=[WapitiFinding(category="Reflected Cross Site Scripting", method="GET", path="/search", parameter="q", module="xss", info="XSS via q", http_request="")],
    )
    nuclei_result = NucleiResult(
        target=cfg.target_origin, duration_s=2.0,
        findings=[NucleiFinding(template_id="exposed-panel", name="Admin panel exposed", severity="medium", description="", matched_at=cfg.target_origin + "/admin")],
    )
    osv_result = OsvResult(
        target=cfg.target_origin, manifests_checked=10, manifests_found=["package-lock.json"], duration_s=1.0,
        vulnerabilities=[OsvVulnerability(manifest_file="package-lock.json", package_name="lodash", package_version="4.17.15", ecosystem="npm", vuln_id="GHSA-xxxx", summary="prototype pollution", severity="HIGH")],
    )
    zap_result = ZapResult(
        target=cfg.target_origin, duration_s=30.0,
        alerts=[ZapAlert(name="SQL Injection", risk="high", confidence="High", url=cfg.target_origin + "/user", param="id", description="", solution="")],
    )

    patches = _patch_all_sub_tools(
        tls=tls_result, cookies=cookie_result, sqlmap=sqlmap_result, wapiti=wapiti_result,
        nuclei=nuclei_result, osv=osv_result, zap=zap_result,
    )
    with patch.multiple("agent.agents.va_agent", **{k.rsplit(".", 1)[1]: v for k, v in patches.items()}):
        result = run_va_agent(cfg, evidence)

    tools_found = {f.extra.get("tool") for f in result.findings}
    assert tools_found == {"tls", "cookies", "sqlmap", "wapiti", "nuclei", "osv-scanner", "zap"}
    assert len(result.findings) == 7
    assert sorted(result.tools_run) == sorted(
        ["nikto", "tls", "cookies", "sqlmap", "wapiti", "nuclei", "osv-scanner", "zap"]
    )
    assert result.tool_errors == {}

    sqlmap_finding = next(f for f in result.findings if f.extra.get("tool") == "sqlmap")
    assert sqlmap_finding.severity == "high"
    assert sqlmap_finding.confidence == "confirmed"


def test_va_agent_skips_unavailable_best_effort_tools_cleanly(tmp_path):
    """nuclei/osv-scanner/zap are best-effort GitHub-release downloads in
    setup.sh -- when their binary isn't present, VA agent must report
    them as a clear per-tool error (not crash, not silently vanish)."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    patches = _patch_all_sub_tools()  # none of nuclei/osv/zap marked "available"
    with patch.multiple("agent.agents.va_agent", **{k.rsplit(".", 1)[1]: v for k, v in patches.items()}):
        result = run_va_agent(cfg, evidence)

    assert "nuclei" in result.tool_errors
    assert "not installed" in result.tool_errors["nuclei"]
    assert "osv-scanner" in result.tool_errors
    assert "zap" in result.tool_errors
    assert result.findings == []


def test_va_agent_isolates_one_sub_tool_crashing_from_the_rest(tmp_path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    nikto_result = NiktoResult(
        target=cfg.target_origin,
        findings=[NiktoFinding(id="1", osvdb=None, method="GET", url=cfg.target_origin, message="some finding")],
        raw_stdout="", returncode=0, duration_s=1.0, truncated=False, error=None,
    )

    def _boom(*a, **k):
        raise RuntimeError("sqlmap is not on PATH. Install it (e.g. `apt install sqlmap`).")

    patches = _patch_all_sub_tools(nikto=nikto_result)
    patches["agent.agents.va_agent.run_sqlmap"] = _boom
    with patch.multiple("agent.agents.va_agent", **{k.rsplit(".", 1)[1]: v for k, v in patches.items()}):
        result = run_va_agent(cfg, evidence)

    # sqlmap's failure is captured as a tool_error, not an exception that
    # kills the whole VA agent -- the other tools' results still come through.
    assert "sqlmap is not on PATH" in result.tool_errors["sqlmap"]
    nikto_findings = [f for f in result.findings if f.extra.get("tool") == "nikto"]
    assert len(nikto_findings) == 1
