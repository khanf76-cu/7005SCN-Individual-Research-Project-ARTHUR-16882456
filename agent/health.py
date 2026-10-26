"""Health check: verifies the artefact's prerequisites are actually
installed and working, rather than letting a missing binary surface as
a confusing crash mid-assessment.

Used three ways:
  1. `python -m agent.health` -- standalone CLI, called by setup.sh at
     the end of installation to confirm everything worked.
  2. The web UI's /health page and /api/health JSON endpoint.
  3. Imported directly by anything that wants a quick pre-flight check
     before starting a run.
"""
from __future__ import annotations

import importlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field

import requests

REQUIRED_PY_PACKAGES = [
    "openai",
    "requests",
    "sklearn",
    "numpy",
    "dotenv",
    "flask",
    "fpdf",
]


@dataclass
class CheckResult:
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str


@dataclass
class HealthReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def overall_status(self) -> str:
        statuses = {c.status for c in self.checks}
        if "fail" in statuses:
            return "fail"
        if "warn" in statuses:
            return "warn"
        return "ok"

    def to_dict(self) -> dict:
        return {
            "overall_status": self.overall_status,
            "checks": [asdict(c) for c in self.checks],
        }


def _check_os(os_release_path=None) -> CheckResult:
    """Preflight OS check: this artefact targets Ubuntu (setup.sh's
    installer step is apt-get based). Not being on Ubuntu doesn't stop
    anything here -- Python/pip/the web UI are OS-agnostic -- but it
    does mean setup.sh's automatic package install assumed a
    Debian/Ubuntu apt environment, so flag it clearly rather than
    letting a mismatch surface later as a confusing missing-binary
    error. `os_release_path` is injectable for testing; defaults to the
    real /etc/os-release."""
    from pathlib import Path

    os_release = os_release_path if os_release_path is not None else Path("/etc/os-release")
    if not os_release.exists():
        return CheckResult(
            "Operating system", "warn",
            f"{sys.platform} -- /etc/os-release not found (not a standard Linux distro); "
            "setup.sh's apt-get step won't apply, see INSTALL.md for a manual install",
        )

    info: dict[str, str] = {}
    for line in os_release.read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            info[key] = value.strip().strip('"')

    distro_id = info.get("ID", "").lower()
    id_like = info.get("ID_LIKE", "").lower()
    pretty = info.get("PRETTY_NAME", distro_id or "unknown")

    if distro_id == "ubuntu":
        return CheckResult("Operating system", "ok", pretty)
    if "debian" in id_like or "ubuntu" in id_like or distro_id == "debian":
        return CheckResult(
            "Operating system", "warn",
            f"{pretty} -- Debian-based but not Ubuntu; setup.sh's apt-get install should "
            "still work, but this artefact is built and tested against Ubuntu",
        )
    return CheckResult(
        "Operating system", "warn",
        f"{pretty} -- not Ubuntu/Debian; setup.sh's apt-get step won't apply here, "
        "use the manual install path in INSTALL.md",
    )


def _check_systemd_service() -> CheckResult:
    """Reports whether arthur.service is installed and, if so, whether
    it's enabled (will start on boot) and currently active. Not a
    failure if it's absent -- plenty of valid setups (containers, WSL,
    manual `python webui/app.py`) never install it."""
    unit_path = "/etc/systemd/system/arthur.service"
    if shutil.which("systemctl") is None or not os.path.exists(unit_path):
        return CheckResult(
            "arthur.service", "warn",
            "not installed -- run 'sudo ./setup.sh' on a systemd machine to install it, "
            "or start the web UI manually with 'python webui/app.py'",
        )
    try:
        enabled = subprocess.run(
            ["systemctl", "is-enabled", "arthur.service"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip()
        active = subprocess.run(
            ["systemctl", "is-active", "arthur.service"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip()
    except (subprocess.TimeoutExpired, OSError) as exc:
        return CheckResult("arthur.service", "warn", f"installed but couldn't query systemctl: {exc}")

    if enabled == "enabled" and active == "active":
        return CheckResult("arthur.service", "ok", "enabled (starts on boot) and active now")
    if enabled == "enabled":
        return CheckResult(
            "arthur.service", "warn",
            f"enabled (starts on boot) but currently {active or 'inactive'} -- "
            "try: systemctl start arthur",
        )
    return CheckResult(
        "arthur.service", "warn",
        f"installed but not enabled for boot (enabled={enabled or 'unknown'}, "
        f"active={active or 'unknown'}) -- try: systemctl enable --now arthur",
    )


def _check_python_version() -> CheckResult:
    version = sys.version.split()[0]
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 10):
        return CheckResult("Python version", "ok", f"Python {version}")
    return CheckResult(
        "Python version", "warn", f"Python {version} -- 3.10+ recommended"
    )


def _check_binary(
    name: str, version_args: list[str] | None, required: bool = True, timeout_s: int = 10
) -> CheckResult:
    """`version_args=None` skips actually invoking the binary and just
    confirms it's on PATH -- used for zap.sh, since ZAP is a full Java
    app that boots a JVM just to print its version (routinely >10s,
    sometimes 20-30s on a slower box), which is both too slow for a
    health check and wasteful to do on every /health page load."""
    path = shutil.which(name)
    if path is None:
        status = "fail" if required else "warn"
        return CheckResult(f"{name} binary", status, f"{name} not found on PATH")

    if version_args is None:
        return CheckResult(f"{name} binary", "ok", f"{path} (version not checked -- too slow to invoke here)")

    try:
        proc = subprocess.run(
            [name] + version_args, capture_output=True, text=True, timeout=timeout_s, check=False
        )
        raw = (proc.stdout or proc.stderr or "").strip().splitlines()
        version_line = raw[0] if raw else "version unknown"
        return CheckResult(f"{name} binary", "ok", f"{path} -- {version_line[:120]}")
    except (subprocess.TimeoutExpired, OSError) as exc:
        return CheckResult(f"{name} binary", "warn", f"found at {path} but version check failed: {exc}")


_PACKAGE_DISTRIBUTION_NAMES = {
    "dotenv": "python-dotenv",
    "sklearn": "scikit-learn",
    "fpdf": "fpdf2",
}


def _check_pip_package(module_name: str) -> CheckResult:
    from importlib.metadata import PackageNotFoundError, version as pkg_version

    try:
        importlib.import_module(module_name)
    except ImportError as exc:
        return CheckResult(f"python package: {module_name}", "fail", f"not importable: {exc}")

    dist_name = _PACKAGE_DISTRIBUTION_NAMES.get(module_name, module_name)
    try:
        version = pkg_version(dist_name)
    except PackageNotFoundError:
        version = "unknown"
    return CheckResult(f"python package: {module_name}", "ok", f"version {version}")


def _check_env_file() -> CheckResult:
    from pathlib import Path

    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return CheckResult(
            ".env file", "warn", ".env not found -- copy .env.example to .env and fill it in"
        )
    return CheckResult(".env file", "ok", str(env_path))


_PLACEHOLDER_KEY_VALUES = {"sk-...", "sk-", "", "your-api-key-here", "changeme"}


def _check_api_key() -> CheckResult:
    from dotenv import load_dotenv

    load_dotenv()
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key or key.lower() in _PLACEHOLDER_KEY_VALUES:
        return CheckResult(
            "OPENAI_API_KEY",
            "fail",
            "not set (still the .env.example placeholder) -- edit .env and add your real key",
        )
    if not re.match(r"^sk-", key) or len(key) < 10:
        return CheckResult("OPENAI_API_KEY", "warn", "set, but doesn't look like a standard OpenAI key (expected sk-... and longer)")
    return CheckResult("OPENAI_API_KEY", "ok", f"set ({len(key)} chars, starts with {key[:3]}...)")


def _check_nvd_reachability(timeout_s: float = 5.0) -> CheckResult:
    try:
        resp = requests.get(
            "https://services.nvd.nih.gov/rest/json/cves/2.0",
            params={"resultsPerPage": 1},
            timeout=timeout_s,
        )
        if resp.status_code in (200, 403, 404):
            # 403/404 without a key still proves the host is reachable;
            # the correlate agent's real queries use keywordSearch, not
            # this bare health-check request.
            return CheckResult("NVD API reachability", "ok", f"HTTP {resp.status_code}")
        return CheckResult("NVD API reachability", "warn", f"unexpected HTTP {resp.status_code}")
    except requests.RequestException as exc:
        return CheckResult("NVD API reachability", "warn", f"unreachable: {exc}")


def _check_write_permissions() -> CheckResult:
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    probe = project_root / ".health_write_probe"
    try:
        probe.write_text("ok")
        probe.unlink()
        return CheckResult("Write permissions", "ok", str(project_root))
    except OSError as exc:
        return CheckResult("Write permissions", "fail", f"cannot write to {project_root}: {exc}")


def run_health_checks(*, check_network: bool = True) -> HealthReport:
    checks = [
        _check_os(),
        _check_python_version(),
        _check_write_permissions(),
        _check_env_file(),
        _check_api_key(),
        _check_binary("nikto", ["-Version"]),
        _check_binary("nmap", ["--version"]),
        _check_binary("sqlmap", ["--version"]),
        _check_binary("wapiti", ["--version"]),
        # nuclei/osv-scanner/zap.sh are setup.sh's best-effort GitHub-release
        # downloads (see setup.sh step 1.5) -- absence is expected, not a
        # failure, if that download didn't succeed on this machine (e.g. no
        # outbound network to GitHub at install time). VA agent already
        # handles each one being unavailable by skipping it cleanly.
        _check_binary("nuclei", ["-version"], required=False),
        _check_binary("osv-scanner", ["--version"], required=False),
        # zap.sh is a full Java app -- invoking it with -version boots a JVM
        # just to print one line, which routinely exceeds a sane health-check
        # timeout (and is wasteful to do on every /health page load anyway).
        # version_args=None skips invoking it: existing on PATH is enough.
        _check_binary("zap.sh", None, required=False),
        _check_systemd_service(),
    ]
    for pkg in REQUIRED_PY_PACKAGES:
        checks.append(_check_pip_package(pkg))

    if check_network:
        checks.append(_check_nvd_reachability())

    return HealthReport(checks=checks)


if __name__ == "__main__":
    report = run_health_checks()
    width = max(len(c.name) for c in report.checks) + 2
    icon = {"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]"}
    for c in report.checks:
        print(f"{icon[c.status]} {c.name.ljust(width)} {c.detail}")
    print()
    print(f"Overall status: {report.overall_status.upper()}")
    sys.exit(0 if report.overall_status != "fail" else 1)
