import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.config import RunConfig
from agent.evidence import EvidenceLogger
from agent.tools.nikto_tool import ScopeViolation, _detect_error, run_nikto

SAMPLE_XML = """<?xml version="1.0" ?>
<!DOCTYPE niktoscan SYSTEM "/usr/share/doc/nikto/nikto.dtd">
<niktoscan version="2.1.5">
<scandetails targetip="127.0.0.1" targethostname="localhost" targetport="8765">
<item id="999976" osvdbid="0" osvdblink="http://osvdb.org/0" method="GET">
<description><![CDATA[The anti-clickjacking X-Frame-Options header is not present.]]></description>
<uri><![CDATA[/]]></uri>
<namelink><![CDATA[http://localhost:8765/]]></namelink>
<iplink><![CDATA[http://127.0.0.1:8765/]]></iplink>
</item>
<item id="001896" osvdbid="3092" osvdblink="http://osvdb.org/3092" method="GET">
<description><![CDATA[/tests/: This might be interesting...]]></description>
<uri><![CDATA[/tests/]]></uri>
<namelink><![CDATA[http://localhost:8765/tests/]]></namelink>
<iplink><![CDATA[http://127.0.0.1:8765/tests/]]></iplink>
</item>
<statistics elapsed="7" itemsfound="2" itemstested="6544" />
</scandetails>
</niktoscan>
"""


def make_config():
    return RunConfig(
        target_origin="http://10.15.20.21:3001",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )


def _fake_completed_process(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["nikto"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_nikto_rejects_out_of_scope_target(tmp_path: Path):
    cfg_out_of_scope = RunConfig(
        target_origin="http://evil.example.com",
        allowed_hosts=("10.15.20.21",),
        openai_api_key="test-key",
        openai_model="gpt-5-mini",
        rag_enabled=False,
    )
    with patch("agent.tools.nikto_tool.nikto_available", return_value=True):
        with pytest.raises(ScopeViolation):
            run_nikto(cfg_out_of_scope, EvidenceLogger(run_id="t", out_dir=tmp_path))


def test_run_nikto_parses_real_findings_from_xml(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        # nikto_tool writes to the -output path itself in real life; here
        # we simulate that by writing the sample XML to wherever it asked.
        out_path = Path(cmd[cmd.index("-output") + 1])
        out_path.write_text(SAMPLE_XML)
        return _fake_completed_process(returncode=0, stdout="+ Target IP: 127.0.0.1\n")

    with patch("agent.tools.nikto_tool.nikto_available", return_value=True), \
         patch("agent.tools.nikto_tool._ensure_nikto_dtd_readable"), \
         patch("agent.tools.nikto_tool.subprocess.run", side_effect=fake_run):
        result = run_nikto(cfg, evidence, max_scan_time_s=15)

    assert result.error is None
    assert not result.truncated
    assert len(result.findings) == 2
    assert result.findings[0].osvdb == "0"
    assert result.findings[0].method == "GET"
    assert "X-Frame-Options" in result.findings[0].message
    assert result.findings[1].osvdb == "3092"


TRUNCATED_XML = """<?xml version="1.0" ?>
<!DOCTYPE niktoscan SYSTEM "/usr/share/doc/nikto/nikto.dtd">
<niktoscan version="2.1.5">
<scandetails targetip="10.15.20.21" targethostname="10.15.20.21" targetport="3001">
<item id="999976" osvdbid="0" osvdblink="http://osvdb.org/0" method="GET">
<description><![CDATA[The anti-clickjacking X-Frame-Options header is not present.]]></description>
<uri><![CDATA[/]]></uri>
<namelink><![CDATA[http://10.15.20.21:3001/]]></namelink>
<iplink><![CDATA[http://10.15.20.21:3001/]]></iplink>
</item>
<item id="001896" osvdbid="3092" osvdblink="http://osvdb.org/3092" method="GET">
<description><![CDATA[/tests/: This might be int"""
# ^ deliberately cut off mid-item, no closing tags anywhere -- this is the
# shape nikto's own `-maxtime` cutoff (or the target going unresponsive
# mid-scan) actually produces: a well-formed first item followed by a
# truncated second one and no closing </scandetails></niktoscan>.


def test_run_nikto_recovers_findings_from_truncated_xml(tmp_path: Path):
    """Regression test: a nikto scan cut short mid-write (e.g. by
    `-maxtime`, or the target becoming unresponsive under the load of
    ARTHUR's own concurrent 8-sub-tool VA pass) used to make the whole
    XML document fail to parse, discarding every finding nikto DID
    manage to write out -- including ones from well before the cutoff.
    The complete first <item> here must still come through."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        out_path = Path(cmd[cmd.index("-output") + 1])
        out_path.write_text(TRUNCATED_XML)
        return _fake_completed_process(returncode=0, stdout="+ Target IP: 10.15.20.21\n")

    with patch("agent.tools.nikto_tool.nikto_available", return_value=True), \
         patch("agent.tools.nikto_tool._ensure_nikto_dtd_readable"), \
         patch("agent.tools.nikto_tool.subprocess.run", side_effect=fake_run):
        result = run_nikto(cfg, evidence, max_scan_time_s=15)

    assert result.truncated is True
    assert result.error is not None and "truncated" in result.error
    assert len(result.findings) == 1  # the complete item recovered; the cut-off one dropped
    assert result.findings[0].osvdb == "0"
    assert "X-Frame-Options" in result.findings[0].message


def test_run_nikto_reports_clear_error_when_xml_totally_unrecoverable(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        out_path = Path(cmd[cmd.index("-output") + 1])
        out_path.write_text("<?xml version=\"1.0\" ?>\n<niktoscan version=\"2.1.5\">\n<scandetails")
        return _fake_completed_process(returncode=0, stdout="+ Target IP: 10.15.20.21\n")

    with patch("agent.tools.nikto_tool.nikto_available", return_value=True), \
         patch("agent.tools.nikto_tool._ensure_nikto_dtd_readable"), \
         patch("agent.tools.nikto_tool.subprocess.run", side_effect=fake_run):
        result = run_nikto(cfg, evidence, max_scan_time_s=15)

    assert result.truncated is True
    assert result.findings == []
    assert result.error is not None and "no complete findings could be recovered" in result.error


def test_run_nikto_surfaces_invalid_format_error_instead_of_zero_findings(tmp_path: Path):
    """Regression test for the original bug: passing an unsupported
    -Format to this nikto build makes it print "+ ERROR: Invalid output
    format" and exit 0 with no output file. That must come back as a
    real error, not a clean "0 findings" result."""
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        # Deliberately do NOT write the output file, matching nikto's
        # real behaviour when it rejects the requested format.
        return _fake_completed_process(returncode=0, stdout="+ ERROR: Invalid output format\n")

    with patch("agent.tools.nikto_tool.nikto_available", return_value=True), \
         patch("agent.tools.nikto_tool._ensure_nikto_dtd_readable"), \
         patch("agent.tools.nikto_tool.subprocess.run", side_effect=fake_run):
        result = run_nikto(cfg, evidence, max_scan_time_s=15)

    assert result.findings == []
    assert result.error is not None
    assert "Invalid output format" in result.error


def test_run_nikto_surfaces_missing_dtd_error(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        return _fake_completed_process(returncode=0, stdout="+ ERROR: reading DTD\n")

    with patch("agent.tools.nikto_tool.nikto_available", return_value=True), \
         patch("agent.tools.nikto_tool._ensure_nikto_dtd_readable"), \
         patch("agent.tools.nikto_tool.subprocess.run", side_effect=fake_run):
        result = run_nikto(cfg, evidence, max_scan_time_s=15)

    assert result.findings == []
    assert "reading DTD" in result.error


def test_run_nikto_handles_timeout(tmp_path: Path):
    cfg = make_config()
    evidence = EvidenceLogger(run_id="test-run", out_dir=tmp_path)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=15, output="partial")

    with patch("agent.tools.nikto_tool.nikto_available", return_value=True), \
         patch("agent.tools.nikto_tool._ensure_nikto_dtd_readable"), \
         patch("agent.tools.nikto_tool.subprocess.run", side_effect=fake_run):
        result = run_nikto(cfg, evidence, max_scan_time_s=15)

    assert result.truncated is True
    assert result.error == "nikto timed out"
    assert result.findings == []


def test_detect_error_returns_none_for_clean_run(tmp_path: Path):
    out_path = tmp_path / "out.xml"
    out_path.write_text("<niktoscan></niktoscan>")
    proc = _fake_completed_process(returncode=0, stdout="+ Target IP: 1.2.3.4\n")
    assert _detect_error(proc, out_path) is None


def test_detect_error_flags_missing_output_file(tmp_path: Path):
    proc = _fake_completed_process(returncode=0, stdout="")
    out_path = tmp_path / "never_written.xml"
    error = _detect_error(proc, out_path)
    assert error is not None
    assert "no output file" in error
