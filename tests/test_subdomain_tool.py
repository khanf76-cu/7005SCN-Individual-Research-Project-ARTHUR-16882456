from pathlib import Path

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.subdomain_tool import run_subdomain_enum


def test_subdomain_enum_skipped_for_literal_ip(tmp_path: Path):
    cfg = RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)
    result = run_subdomain_enum(cfg, evidence)

    assert result.applicable is False
    assert result.hits == []
    assert "literal IP" in result.skip_reason

    log_lines = evidence.evidence_path.read_text().strip().splitlines()
    assert any("TOOL_SKIPPED" in line for line in log_lines)


def test_subdomain_enum_applicable_for_domain_target(tmp_path: Path, monkeypatch):
    cfg = RunConfig(
        target_origin="http://example-not-a-real-domain-xyz.test:3001",
        allowed_hosts=("example-not-a-real-domain-xyz.test",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    # DNS lookups will genuinely fail for this fake domain, which is fine --
    # we're testing that the applicable path runs and returns an empty hit
    # list rather than being skipped as not-applicable.
    result = run_subdomain_enum(cfg, evidence, timeout_s=0.5)

    assert result.applicable is True
    assert result.skip_reason is None
    assert result.base_domain == "example-not-a-real-domain-xyz.test"
