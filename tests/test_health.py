import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent.health import (
    HealthReport,
    CheckResult,
    _check_api_key,
    _check_binary,
    _check_os,
    _check_pip_package,
    _check_systemd_service,
    run_health_checks,
)


def test_check_binary_reports_fail_when_missing():
    with patch("agent.health.shutil.which", return_value=None):
        result = _check_binary("nonexistent-tool-xyz", ["--version"])
    assert result.status == "fail"
    assert "not found" in result.detail


def test_check_binary_reports_ok_when_present():
    fake_proc = MagicMock(stdout="nikto 2.5.0\n", stderr="", returncode=0)
    with patch("agent.health.shutil.which", return_value="/usr/bin/nikto"), \
         patch("agent.health.subprocess.run", return_value=fake_proc):
        result = _check_binary("nikto", ["-Version"])
    assert result.status == "ok"
    assert "nikto 2.5.0" in result.detail


def test_check_binary_skips_invocation_when_version_args_is_none():
    """zap.sh-style check: existence on PATH is enough, never shells out
    (ZAP boots a JVM just to print -version, which is too slow for a
    health check and wasteful to run on every /health page load)."""
    with patch("agent.health.shutil.which", return_value="/usr/local/bin/zap.sh"), \
         patch("agent.health.subprocess.run") as mock_run:
        result = _check_binary("zap.sh", None, required=False)
    assert result.status == "ok"
    assert "/usr/local/bin/zap.sh" in result.detail
    mock_run.assert_not_called()


def test_check_binary_version_args_none_still_warns_when_missing():
    with patch("agent.health.shutil.which", return_value=None):
        result = _check_binary("zap.sh", None, required=False)
    assert result.status == "warn"
    assert "not found" in result.detail


def test_check_pip_package_ok_for_real_package():
    result = _check_pip_package("requests")
    assert result.status == "ok"


def test_check_pip_package_fail_for_missing_package():
    result = _check_pip_package("definitely_not_a_real_package_xyz123")
    assert result.status == "fail"


def test_health_report_overall_status_fail_dominates():
    report = HealthReport(
        checks=[
            CheckResult("a", "ok", ""),
            CheckResult("b", "warn", ""),
            CheckResult("c", "fail", ""),
        ]
    )
    assert report.overall_status == "fail"


def test_health_report_overall_status_warn_without_fail():
    report = HealthReport(checks=[CheckResult("a", "ok", ""), CheckResult("b", "warn", "")])
    assert report.overall_status == "warn"


def test_health_report_overall_status_ok_when_all_ok():
    report = HealthReport(checks=[CheckResult("a", "ok", ""), CheckResult("b", "ok", "")])
    assert report.overall_status == "ok"


def test_health_report_to_dict_shape():
    report = HealthReport(checks=[CheckResult("a", "ok", "detail")])
    d = report.to_dict()
    assert d["overall_status"] == "ok"
    assert d["checks"][0]["name"] == "a"


def test_run_health_checks_without_network_skips_nvd():
    report = run_health_checks(check_network=False)
    names = [c.name for c in report.checks]
    assert "NVD API reachability" not in names
    assert "Python version" in names


def test_check_api_key_rejects_env_example_placeholder(monkeypatch):
    # Regression test: a freshly-copied .env.example has
    # OPENAI_API_KEY=sk-... which must NOT pass as a valid key.
    # load_dotenv() never overrides an already-set env var, so setting
    # it here is sufficient without needing to touch the .env file.
    monkeypatch.setenv("OPENAI_API_KEY", "sk-...")
    result = _check_api_key()
    assert result.status == "fail"
    assert "placeholder" in result.detail


def test_check_api_key_accepts_real_looking_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890")
    result = _check_api_key()
    assert result.status == "ok"


def test_check_api_key_fails_when_unset(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = _check_api_key()
    assert result.status == "fail"


def test_check_os_reports_ok_for_ubuntu(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n')
    result = _check_os(os_release)
    assert result.status == "ok"
    assert "Ubuntu 22.04.4 LTS" in result.detail


def test_check_os_warns_for_debian_based_non_ubuntu(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=debian\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    result = _check_os(os_release)
    assert result.status == "warn"
    assert "Debian-based" in result.detail


def test_check_os_warns_for_unrelated_distro(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=fedora\nPRETTY_NAME="Fedora Linux 40"\n')
    result = _check_os(os_release)
    assert result.status == "warn"
    assert "not Ubuntu/Debian" in result.detail


def test_check_os_warns_when_os_release_missing(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = _check_os(missing)
    assert result.status == "warn"


def test_check_systemd_service_warns_when_not_installed():
    with patch("agent.health.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("agent.health.os.path.exists", return_value=False):
        result = _check_systemd_service()
    assert result.status == "warn"
    assert "not installed" in result.detail


def test_check_systemd_service_ok_when_enabled_and_active():
    enabled_proc = MagicMock(stdout="enabled\n")
    active_proc = MagicMock(stdout="active\n")
    with patch("agent.health.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("agent.health.os.path.exists", return_value=True), \
         patch("agent.health.subprocess.run", side_effect=[enabled_proc, active_proc]):
        result = _check_systemd_service()
    assert result.status == "ok"
    assert "enabled" in result.detail and "active" in result.detail


def test_check_systemd_service_warns_when_enabled_but_inactive():
    enabled_proc = MagicMock(stdout="enabled\n")
    inactive_proc = MagicMock(stdout="inactive\n")
    with patch("agent.health.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("agent.health.os.path.exists", return_value=True), \
         patch("agent.health.subprocess.run", side_effect=[enabled_proc, inactive_proc]):
        result = _check_systemd_service()
    assert result.status == "warn"
    assert "start arthur" in result.detail


def test_run_health_checks_with_network_includes_nvd(monkeypatch):
    import agent.health as health_module

    with patch.object(health_module, "_check_nvd_reachability", return_value=CheckResult("NVD API reachability", "ok", "mocked")):
        report = run_health_checks(check_network=True)
    names = [c.name for c in report.checks]
    assert "NVD API reachability" in names
