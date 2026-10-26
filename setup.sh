#!/usr/bin/env bash
#
# setup.sh -- one-shot installer for the ARTHUR coursework artefact.
#
# Updates and fully upgrades the system (apt update/upgrade/
# dist-upgrade), installs system packages (nikto, nmap, python3-venv,
# build tools), creates a Python virtual environment, installs the pip
# requirements, scaffolds .env from .env.example, installs and starts
# ARTHUR as a systemd service (arthur.service) pointed at this install,
# and finishes by running the health check so you can see immediately
# whether everything worked.
#
# Usage:
#   sudo ./setup.sh
#
# Safe to re-run. If ARTHUR is already installed (arthur.service and/or
# an existing .venv), it purges that install first (stops/removes the
# service, deletes the old venv) and reinstalls clean -- everything
# else (apt packages, .env, past scan results) is left alone/updated
# in place rather than wiped.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------
# 0. Must run as root (apt install needs it), but Python/venv/pip steps
#    run as the invoking user so the venv and its files aren't
#    root-owned afterwards.
# ---------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "This script installs system packages and must be run with sudo:"
  echo "  sudo ./setup.sh"
  exit 1
fi

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"

echo "=== ARTHUR setup ==="
echo "Project directory: $SCRIPT_DIR"
echo "Installing as root, Python steps will run as: $REAL_USER"
echo

run_as_user() {
  sudo -u "$REAL_USER" -H bash -c "$1"
}

# ---------------------------------------------------------------------
# 0.4. Make sure the project directory is actually owned by the user
#      the Python/venv/pip steps below will run as.
#
#    If this directory was extracted/cloned while already root (e.g.
#    `sudo unzip ...`, or scp'd in as root, or `sudo -i` then unzip),
#    it ends up root:root, and every run_as_user step below would fail
#    with "Permission denied" trying to write into it. Re-owning it
#    here makes setup.sh work the same way regardless of how the files
#    got onto the machine.
# ---------------------------------------------------------------------
CURRENT_OWNER="$(stat -c '%U' "$SCRIPT_DIR")"
if [[ "$CURRENT_OWNER" != "$REAL_USER" ]]; then
  echo "--- Fixing ownership: $SCRIPT_DIR is owned by $CURRENT_OWNER, needs to be $REAL_USER ---"
  chown -R "$REAL_USER":"$REAL_USER" "$SCRIPT_DIR"
  echo
fi

# ---------------------------------------------------------------------
# 0.45. Purge any previous ARTHUR install before reinstalling.
#
#    Unlike the rest of this script (which is additive/idempotent --
#    skips a step if its target already exists), this one is
#    deliberately destructive on purpose: it removes the systemd
#    service and the old virtual environment so every run starts from
#    a clean, known-good state rather than layering a new install on
#    top of a possibly-stale one. What it does NOT touch: .env (your
#    API key), and anything under webui_runs/ or evidence/ (your past
#    scan results) -- those are your data, not install artefacts.
# ---------------------------------------------------------------------
PURGED_SOMETHING=0

if [[ -f /etc/systemd/system/arthur.service ]]; then
  echo "--- ARTHUR is already installed as a service -- purging it first ---"
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl stop arthur.service 2>/dev/null || true
    systemctl disable arthur.service 2>/dev/null || true
  fi
  rm -f /etc/systemd/system/arthur.service
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl daemon-reload 2>/dev/null || true
  fi
  echo "Removed old arthur.service."
  PURGED_SOMETHING=1
fi

if [[ -d "$SCRIPT_DIR/.venv" ]]; then
  echo "--- Found an existing virtual environment -- purging it for a clean reinstall ---"
  rm -rf "$SCRIPT_DIR/.venv"
  echo "Removed old .venv."
  PURGED_SOMETHING=1
fi

if [[ $PURGED_SOMETHING -eq 1 ]]; then
  echo "Purge complete -- reinstalling fresh from here."
  echo
fi

# ---------------------------------------------------------------------
# 0.5. Preflight: confirm this is Ubuntu.
#
#    This artefact's automatic install path (the apt-get block below)
#    is built and tested against Ubuntu. Doesn't block anything --
#    Debian-based distros will generally work fine via the same
#    apt-get commands -- but it's worth telling you up front rather
#    than letting a mismatch surface later as a confusing package
#    error. The full preflight (OS + every binary/library/tool) is
#    re-checked at the end of this script and on the web UI's /health
#    page any time after.
# ---------------------------------------------------------------------
echo "--- Preflight: checking OS ---"
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DETECTED_OS="${PRETTY_NAME:-${ID:-unknown}}"
  if [[ "${ID:-}" == "ubuntu" ]]; then
    echo "OK: running on $DETECTED_OS"
  elif [[ "${ID_LIKE:-}" == *debian* || "${ID:-}" == "debian" ]]; then
    echo "WARN: running on $DETECTED_OS (Debian-based, not Ubuntu)."
    echo "      This artefact targets Ubuntu; the apt-get install below should"
    echo "      still work, but it hasn't been tested on this distro."
  else
    echo "WARN: running on $DETECTED_OS -- not Ubuntu/Debian."
    echo "      The apt-get install step below will likely fail. See"
    echo "      INSTALL.md for a manual install path on other distros."
  fi
else
  echo "WARN: /etc/os-release not found -- can't confirm this is Ubuntu."
fi
echo

# ---------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a  # don't pop up an interactive "restart services?" dialog
  APT_CONF_OPTS=(-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

  echo "--- Updating package lists (apt update) ---"
  apt-get update -qq

  echo "--- Upgrading installed packages (apt upgrade) ---"
  apt-get "${APT_CONF_OPTS[@]}" upgrade -y -qq

  echo "--- Full upgrade, including package removals/additions if needed (apt dist-upgrade) ---"
  apt-get "${APT_CONF_OPTS[@]}" dist-upgrade -y -qq

  echo "--- Installing this artefact's packages (apt install) ---"
  apt-get install -y -qq \
    nikto \
    nmap \
    sqlmap \
    default-jre-headless \
    python3 \
    python3-venv \
    python3-pip \
    build-essential \
    dnsutils \
    curl \
    unzip \
    tar

  echo "--- Removing now-unneeded packages (apt autoremove) ---"
  apt-get autoremove -y -qq || true

  # Minimal/cloud Ubuntu images strip /usr/share/doc/* via a dpkg policy
  # (/etc/dpkg/dpkg.cfg.d/*) to save space. nikto's own .deb happens to
  # keep a *functionally required* file under that path (its XML output
  # DTD), so once docs are stripped, `nikto -Format xml` fails with
  # "+ ERROR: reading DTD" and silently produces no output. nikto only
  # checks that this file exists and is readable -- it never parses or
  # validates against it (it's just a path string nikto puts in the
  # output's DOCTYPE declaration) -- so a harmless placeholder fixes it.
  # agent/tools/nikto_tool.py does this same self-heal at scan time too,
  # as a second line of defence (e.g. if a later unattended apt upgrade
  # strips it again).
  NIKTO_DTD_PATH="$(sed -n 's/^\s*NIKTODTD\s*=\s*\(\S*\).*/\1/p' /etc/nikto/config.txt 2>/dev/null | head -1)"
  if [[ -n "$NIKTO_DTD_PATH" && ! -r "$NIKTO_DTD_PATH" ]]; then
    echo "--- Restoring nikto's stripped XML output DTD at $NIKTO_DTD_PATH ---"
    mkdir -p "$(dirname "$NIKTO_DTD_PATH")"
    echo "<!-- placeholder: nikto only checks this file exists and is readable -->" > "$NIKTO_DTD_PATH"
    chmod 644 "$NIKTO_DTD_PATH"
  fi

  if [[ -f /var/run/reboot-required ]]; then
    echo
    echo "!! A system upgrade just installed updates that need a reboot"
    echo "!! (kernel/libc, typically) to fully take effect:"
    cat /var/run/reboot-required.pkgs 2>/dev/null | sed 's/^/!!   - /' || true
    echo "!! ARTHUR itself will still run fine without rebooting now --"
    echo "!! reboot whenever is convenient."
  fi
elif command -v brew >/dev/null 2>&1; then
  echo "--- Installing system packages (Homebrew) ---"
  echo "NOTE: Homebrew installs should not be run as root. Re-run this"
  echo "block yourself without sudo if this section fails:"
  echo "  brew install nikto nmap python3"
  sudo -u "$REAL_USER" brew install nikto nmap python3 || true
else
  echo "!! No supported package manager (apt-get or brew) found."
  echo "!! Install nikto, nmap, and python3 (3.10+) manually, then re-run"
  echo "!! this script -- it will skip the parts that already succeeded."
fi
echo

# ---------------------------------------------------------------------
# 1.5. Best-effort install of the three VA sub-tools that aren't
#      apt-packaged: nuclei, osv-scanner, and OWASP ZAP. Each is a
#      prebuilt binary downloaded from its GitHub releases, installed to
#      /usr/local/bin (or /opt for ZAP, which is a whole small app
#      directory, not one binary).
#
#      Deliberately non-fatal: `set -e` is relaxed for this block only.
#      If a download fails for any reason (no outbound network to
#      GitHub from this machine, a changed release asset naming
#      convention upstream, GitHub rate-limiting an anonymous API
#      call, ...) this prints a clear warning and moves on rather than
#      aborting the whole install. agent/tools/{nuclei,osv,zap}_tool.py
#      each check for their binary at scan time and report themselves
#      as cleanly unavailable (not a crash) if it's missing -- the rest
#      of the VA pass (nikto, tls, cookies, sqlmap, wapiti) still runs
#      and the report says plainly which of these three didn't run.
#      Safe to re-run: each one skips straight to "already installed"
#      if it's already on PATH.
# ---------------------------------------------------------------------
set +e

github_latest_tag() {
  # Prints the latest release tag (with any leading "v" stripped) for
  # "owner/repo", or nothing if the GitHub API can't be reached /
  # parsed -- callers check for an empty result.
  curl -fsSL --max-time 15 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
    | grep -oP '"tag_name"\s*:\s*"v?\K[^"]+' | head -1
}

echo "--- Installing nuclei (best-effort, downloaded from GitHub releases) ---"
if command -v nuclei >/dev/null 2>&1; then
  echo "nuclei already installed, skipping."
else
  NUCLEI_VERSION="$(github_latest_tag projectdiscovery/nuclei)"
  if [[ -n "$NUCLEI_VERSION" ]]; then
    NUCLEI_ZIP="/tmp/nuclei_install.zip"
    if curl -fsSL --max-time 120 -o "$NUCLEI_ZIP" \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
      && unzip -o -q "$NUCLEI_ZIP" -d /tmp/nuclei_extract \
      && install -m 755 /tmp/nuclei_extract/nuclei /usr/local/bin/nuclei; then
      echo "nuclei $NUCLEI_VERSION installed to /usr/local/bin/nuclei"
      echo "Downloading nuclei's vulnerability template set (one-time, can take a minute)..."
      nuclei -update-templates -silent >/dev/null 2>&1 \
        && echo "nuclei templates updated" \
        || echo "!! WARN: nuclei -update-templates failed -- nuclei will have no templates to scan with until this is re-run manually."
    else
      echo "!! WARN: nuclei download/install failed (asset naming may have changed, or"
      echo "!! no outbound network to GitHub right now). Skipping -- VA agent will"
      echo "!! report nuclei unavailable and skip it cleanly on each scan."
    fi
    rm -rf "$NUCLEI_ZIP" /tmp/nuclei_extract
  else
    echo "!! WARN: couldn't resolve nuclei's latest GitHub release -- skipping install."
  fi
fi
echo

echo "--- Installing osv-scanner (best-effort, downloaded from GitHub releases) ---"
if command -v osv-scanner >/dev/null 2>&1; then
  echo "osv-scanner already installed, skipping."
else
  OSV_VERSION="$(github_latest_tag google/osv-scanner)"
  if [[ -n "$OSV_VERSION" ]]; then
    if curl -fsSL --max-time 60 -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
      && chmod 755 /usr/local/bin/osv-scanner; then
      echo "osv-scanner $OSV_VERSION installed to /usr/local/bin/osv-scanner"
    else
      rm -f /usr/local/bin/osv-scanner
      echo "!! WARN: osv-scanner download/install failed. Skipping -- VA agent will"
      echo "!! report osv-scanner unavailable and skip it cleanly on each scan."
    fi
  else
    echo "!! WARN: couldn't resolve osv-scanner's latest GitHub release -- skipping install."
  fi
fi
echo

echo "--- Installing OWASP ZAP (best-effort, downloaded from GitHub releases) ---"
if command -v zap.sh >/dev/null 2>&1; then
  echo "ZAP already installed, skipping."
else
  ZAP_VERSION="$(github_latest_tag zaproxy/zaproxy)"
  if [[ -n "$ZAP_VERSION" ]]; then
    ZAP_TARBALL="/tmp/zap_install.tar.gz"
    ZAP_INSTALLED=0
    # Release asset naming has varied between dot- and
    # underscore-separated versions across ZAP releases -- try both
    # rather than guess wrong and silently skip a working release.
    for ZAP_ASSET_VERSION in "$ZAP_VERSION" "${ZAP_VERSION//./_}"; do
      if curl -fsSL --max-time 180 -o "$ZAP_TARBALL" \
        "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_ASSET_VERSION}_Linux.tar.gz"; then
        ZAP_INSTALLED=1
        break
      fi
    done
    if [[ $ZAP_INSTALLED -eq 1 ]]; then
      rm -rf /opt/zaproxy
      mkdir -p /opt/zaproxy
      if tar -xzf "$ZAP_TARBALL" -C /opt/zaproxy --strip-components=1 \
        && ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap.sh; then
        echo "ZAP $ZAP_VERSION installed to /opt/zaproxy (linked as /usr/local/bin/zap.sh)"
      else
        echo "!! WARN: ZAP archive downloaded but extraction/linking failed. Skipping."
      fi
    else
      echo "!! WARN: ZAP download/install failed (asset naming may have changed, or"
      echo "!! no outbound network to GitHub right now). Skipping -- VA agent will"
      echo "!! report ZAP unavailable and skip it cleanly on each scan."
    fi
    rm -f "$ZAP_TARBALL"
  else
    echo "!! WARN: couldn't resolve ZAP's latest GitHub release -- skipping install."
  fi
fi
echo

set -euo pipefail

# ---------------------------------------------------------------------
# 2. Python virtual environment
# ---------------------------------------------------------------------
echo "--- Setting up Python virtual environment ---"
if [[ ! -d "$SCRIPT_DIR/.venv" ]]; then
  run_as_user "cd '$SCRIPT_DIR' && python3 -m venv .venv"
  echo "Created .venv"
else
  echo ".venv already exists, skipping creation"
fi
echo

# ---------------------------------------------------------------------
# 3. Python dependencies
# ---------------------------------------------------------------------
echo "--- Installing Python packages into .venv ---"
run_as_user "cd '$SCRIPT_DIR' && .venv/bin/pip install --quiet --upgrade pip"
run_as_user "cd '$SCRIPT_DIR' && .venv/bin/pip install --quiet -r requirements.txt"
echo "Python packages installed"
echo

# ---------------------------------------------------------------------
# 4. .env scaffolding
# ---------------------------------------------------------------------
echo "--- Setting up .env ---"
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
  chown "$REAL_USER" "$SCRIPT_DIR/.env"
  echo "Created .env from .env.example -- EDIT IT NOW to add your"
  echo "OPENAI_API_KEY before running a scan:"
  echo "  nano $SCRIPT_DIR/.env"
else
  echo ".env already exists, leaving it as-is"
fi
echo

# ---------------------------------------------------------------------
# 5. Install ARTHUR as a systemd service
#
#    Writes a unit file that points directly at this install (this
#    directory's venv and webui/app.py are what the service runs), so
#    the web UI starts automatically and keeps running without a
#    terminal attached, and restarts itself if it crashes.
# ---------------------------------------------------------------------
SERVICE_INSTALLED=0
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  echo "--- Installing arthur.service (systemd) ---"
  cat > /etc/systemd/system/arthur.service <<EOF
[Unit]
Description=ARTHUR pentest artefact web UI
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$REAL_USER
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/.venv/bin/python $SCRIPT_DIR/webui/app.py
Restart=always
RestartSec=3
StartLimitIntervalSec=0
Environment=PYTHONUNBUFFERED=1
# .venv/bin first so the pip-installed wapiti3 CLI (agent/tools/wapiti_tool.py
# calls it as a subprocess, via shutil.which("wapiti")) is found -- systemd
# services don't inherit a shell's PATH, so without this the venv's own
# installed console-script binaries would be invisible to this service
# even though `.venv/bin/pip install` put them right there.
Environment=PATH=$SCRIPT_DIR/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF
  # enable (persists across reboots, written into the boot targets)
  # and start (so it's running right now too) are deliberately two
  # separate calls rather than `enable --now`, so a failure in one is
  # distinguishable from a failure in the other.
  if systemctl daemon-reload && systemctl enable arthur.service; then
    BOOT_ENABLED=1
  else
    BOOT_ENABLED=0
  fi

  if [[ $BOOT_ENABLED -eq 1 ]] && systemctl start arthur.service; then
    SERVICE_INSTALLED=1
    echo "arthur.service installed, enabled for boot, and started."
    echo "Verifying..."
    sleep 1
    systemctl --no-pager status arthur.service || true
    echo "Manage it with: systemctl {status|stop|start|restart} arthur"
  elif [[ $BOOT_ENABLED -eq 1 ]]; then
    echo "!! arthur.service is enabled for boot, but couldn't be started"
    echo "!! here (systemd manager not reachable -- common inside a"
    echo "!! container). It will still start automatically on a real boot."
    echo "!! To start it manually right now: systemctl start arthur"
  else
    echo "!! Wrote /etc/systemd/system/arthur.service but couldn't enable/"
    echo "!! start it here (systemd manager not reachable -- common inside"
    echo "!! a container). On a real machine/VM with systemd as init, run:"
    echo "!!   systemctl daemon-reload && systemctl enable --now arthur"
  fi
else
  echo "!! No systemd init detected on this system -- skipping service"
  echo "!! install. Run the web UI manually instead:"
  echo "!!   source .venv/bin/activate && python webui/app.py"
fi
echo

# ---------------------------------------------------------------------
# 6. Health check
# ---------------------------------------------------------------------
echo "--- Running health check ---"
set +e
# PATH is prepended with .venv/bin here to match exactly what
# arthur.service's own Environment=PATH sees (step 5 above) -- without
# this, the health check would wrongly warn that wapiti (pip-installed
# into .venv) is missing, even though the deployed service finds it fine.
run_as_user "cd '$SCRIPT_DIR' && PATH=\"$SCRIPT_DIR/.venv/bin:\$PATH\" .venv/bin/python -m agent.health"
HEALTH_EXIT=$?
set -e
echo

if [[ $HEALTH_EXIT -eq 0 ]]; then
  echo "=== Setup complete. Health check passed (or warnings only). ==="
else
  echo "=== Setup finished, but the health check reported failures. ==="
  echo "Common fixes:"
  echo "  - Add your OpenAI key to .env (OPENAI_API_KEY=sk-...)"
  echo "  - If nikto/nmap still show missing, check your package"
  echo "    manager's output above for errors"
fi

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo
echo "Next steps:"
if [[ $SERVICE_INSTALLED -eq 1 ]]; then
  echo "  1. Edit .env if you haven't already: nano $SCRIPT_DIR/.env"
  echo "  2. systemctl restart arthur   (picks up your .env changes)"
  echo "  3. Open the web UI -- it listens on all interfaces by default:"
  echo "       http://127.0.0.1:5000/  (on this machine)"
  if [[ -n "$LAN_IP" ]]; then
    echo "       http://$LAN_IP:5000/  (from another machine on this network)"
  fi
  echo "     Check the System Health page once it's open."
  echo
  echo "  arthur.service is already running and will start automatically"
  echo "  on boot. View its logs with: journalctl -u arthur -f"
else
  echo "  1. source .venv/bin/activate"
  echo "  2. Edit .env if you haven't already"
  echo "  3. python webui/app.py"
  echo "  4. Open the web UI -- it listens on all interfaces by default:"
  echo "       http://127.0.0.1:5000/  (on this machine)"
  if [[ -n "$LAN_IP" ]]; then
    echo "       http://$LAN_IP:5000/  (from another machine on this network)"
  fi
  echo "     Check the System Health page once it's open."
fi
echo
echo "No login is required for the web UI, only the per-scan authorization"
echo "checkbox -- don't expose port 5000 beyond a network you trust. Set"
echo "WEBUI_HOST=127.0.0.1 in .env to restrict it to this machine only."
