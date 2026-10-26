# Installing ARTHUR

This is a standalone install guide. For what the tool does and how to use
it once it's running, see `README.md`.

There are two ways to install: the one-command script (recommended), or
manual setup if you can't or don't want to use `sudo`.

---

## Option A: one command (recommended)

```bash
sudo ./setup.sh
```

That's it. `setup.sh` is safe to re-run -- every step checks whether its
target already exists before acting, so running it twice won't reinstall
things or break anything.

### What it actually does

1. **Full system update** -- runs `apt update`, then `apt upgrade` and
   `apt dist-upgrade` (non-interactively, keeping your existing config
   files on any conflict), then `apt autoremove`. This brings the whole
   machine's packages current, not just this project's dependencies --
   if it pulls in a kernel/libc update, you'll see a note at the end
   saying a reboot would be good when convenient (ARTHUR itself runs
   fine either way).
2. **System packages** -- installs `nikto`, `nmap`, `sqlmap`,
   `default-jre-headless` (for OWASP ZAP, step 2.5), `python3`,
   `python3-venv`, `python3-pip`, and a couple of small build/DNS/download
   utilities via `apt-get` (Debian/Ubuntu). If `apt-get` isn't found it
   falls back to printing a `brew install nikto nmap python3` command for
   macOS instead (Homebrew refuses to run as root, so that line runs
   without `sudo`).
2.5. **Best-effort install of nuclei, osv-scanner, and OWASP ZAP** --
   none of these three are apt-packaged, so `setup.sh` downloads a
   prebuilt binary for each from its GitHub releases. This step is
   deliberately non-fatal: if a download fails for any reason (no
   outbound network to GitHub right now, a changed release asset name
   upstream, GitHub API rate-limiting), it prints a clear warning and
   moves on rather than aborting the rest of the install. The VA agent's
   `tool_errors` reporting (see README.md) shows plainly, on every scan,
   which of these three didn't run and why -- so a missing one here is
   visible, not silently swallowed into a "0 findings" result. Re-run
   `setup.sh` later to retry a failed download once network access is
   available.
3. **Python virtual environment** -- creates `.venv/` in the project
   directory, owned by the user who invoked `sudo` (not root), so you can
   activate and use it normally afterwards.
4. **Python dependencies** -- installs everything in `requirements.txt`
   into `.venv`, including `wapiti3` (a VA scanning tool, invoked as a
   subprocess the same way nikto/nmap are, not imported as a library).
5. **`.env` scaffolding** -- if `.env` doesn't exist yet, copies
   `.env.example` to `.env` and hands it ownership. You still need to
   open it and add your real `OPENAI_API_KEY`.
6. **systemd service** -- on a system actually running systemd as PID 1
   (a real machine or VM, not most containers), writes
   `/etc/systemd/system/arthur.service` pointed directly at this
   install's `.venv` and `webui/app.py`, waits for the network to be up
   before starting (`Wants=network-online.target`), and is enabled for
   every future boot (`systemctl enable`) in addition to being started
   right now (`systemctl start`) -- so a reboot brings the web UI back
   up on its own, and `Restart=always` means it also comes back on its
   own if the process ever crashes. The unit's `PATH` is explicitly set
   to put `.venv/bin` first, so the pip-installed `wapiti` CLI (which
   lands in `.venv/bin`, not a system directory) is found by the running
   service -- systemd doesn't inherit a shell's `PATH` the way a
   terminal session does. If systemd isn't available here,
   this step is skipped with a message, and you just run the web UI
   manually instead (step 3 under "after it finishes" below). Either
   way, the health check (and `/health` on the web UI) reports whether
   the service is installed, enabled for boot, and currently active.
7. **Health check** -- runs `python -m agent.health` at the end and
   prints a clear pass/fail summary, so you know immediately whether
   anything needs attention.

### After it finishes

**If `setup.sh` installed `arthur.service`** (you'll see "arthur.service
installed, enabled, and started" in its output):

```bash
nano .env                  # add your OPENAI_API_KEY
systemctl restart arthur   # picks up the change
```

The web UI is already running in the background and will keep running
across reboots. Useful commands:

```bash
systemctl status arthur    # is it up?
journalctl -u arthur -f    # tail its logs
systemctl restart arthur   # after any .env change
```

**Otherwise** (no systemd detected -- common inside containers/WSL),
run it manually whenever you want it up:

```bash
source .venv/bin/activate
nano .env                 # add your OPENAI_API_KEY
python webui/app.py
```

Either way, open `http://127.0.0.1:5000/` in a browser, and check the
**system health** page (linked in the nav) to confirm everything is green
before running a real scan.

---

## Option B: manual install

Use this if you don't have (or don't want to use) `sudo` -- for example on
a shared machine or inside a container where someone else manages system
packages.

### 1. Install the scanner binaries

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y nikto nmap sqlmap default-jre-headless python3 python3-venv python3-pip
```

**macOS (Homebrew):**
```bash
brew install nikto nmap sqlmap python3
```

**Other platforms:** install `nikto`, `nmap`, and `sqlmap` however your
package manager provides them, and make sure `python3` (3.10+) is on
your `PATH`. `wapiti3` installs as part of step 2 below (it's a pip
package). If you truly cannot install one of these binaries, the agent
that uses it will simply report that one sub-tool skipped in its results
rather than crashing the whole run -- but you'll get noticeably weaker
coverage without them.

**Optional (nuclei, osv-scanner, OWASP ZAP):** `setup.sh` downloads
these three automatically from GitHub releases (see Option A). For a
manual install, grab the matching Linux binary for your architecture
from each project's own releases page and put it on your `PATH`:
[nuclei](https://github.com/projectdiscovery/nuclei/releases),
[osv-scanner](https://github.com/google/osv-scanner/releases),
[OWASP ZAP](https://www.zaproxy.org/download/) (needs a JRE: `apt install
default-jre-headless`). All three are optional -- the VA agent reports
each one as cleanly unavailable and skips it if it's missing, rather than
failing.

### 2. Create a virtual environment and install Python packages

```bash
cd pentest_agent
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure your `.env`

```bash
cp .env.example .env
```

Open `.env` and set at minimum:
- `OPENAI_API_KEY` -- your real OpenAI key (starts with `sk-`)

Everything else in `.env` has a sensible default and is optional
(`OPENAI_MODEL`, `TARGET_ORIGIN`, `RAG_ENABLED`, `NVD_API_KEY`).

### 4. Verify

```bash
python -m agent.health
```

You should see a line per check with `[OK]`, `[WARN]`, or `[FAIL]`, and an
overall status at the bottom. Fix anything marked `[FAIL]` before running
a scan -- `[WARN]` is informational and won't block anything.

---

## Verifying the install (either option)

Two equivalent ways to check everything is in place:

**CLI:**
```bash
.venv/bin/python -m agent.health
```

**Web UI:** start the server (`python webui/app.py`) and open
`http://127.0.0.1:5000/health`. It runs the same checks and also exposes
them as JSON at `/api/health` (the home page polls this on load to show a
small status badge).

### What each check covers

| Check | What it means if it fails |
|---|---|
| Operating system | Not Ubuntu (or not Debian-based) -- `setup.sh`'s apt-get install step is built against Ubuntu; a warning here means use the manual install path instead. Never fails the overall check -- Python/the web UI work on any OS. |
| Python version | Interpreter is older than 3.10 -- upgrade Python. |
| Write permissions | The project directory isn't writable by the current user -- fix ownership/permissions. |
| `.env` file | `.env` is missing -- copy `.env.example` to `.env`. |
| `OPENAI_API_KEY` | Not set, or still the `.env.example` placeholder -- edit `.env` and add a real key. The correlate agent can't call the LLM without this. |
| `nikto` binary | Not found on `PATH` -- the VA agent's nikto scans will be skipped. |
| `nmap` binary | Not found on `PATH` -- the nmap agent can't run at all. |
| `sqlmap` binary | Not found on `PATH` -- the VA agent's SQL-injection check will be skipped. |
| `wapiti` binary | Not found on `PATH` -- the VA agent's active-fuzzing checks (XSS/SQLi/CSRF/etc.) will be skipped. Re-run `pip install -r requirements.txt` into `.venv` if this fails after `setup.sh` reported no errors. |
| `nuclei` / `osv-scanner` / `zap.sh` binary | `[WARN]`, not `[FAIL]`, if missing -- these three are best-effort GitHub-release downloads (see "What it actually does" step 2.5). A warning here just means that one sub-tool didn't install; everything else still works, and VA's `tool_errors` reporting shows this on every scan too. Re-run `setup.sh` to retry. |
| `arthur.service` | Not installed -- `setup.sh` only installs it on a machine actually running systemd as PID 1; otherwise run the web UI manually. If it says "installed but not enabled/active", run `systemctl enable --now arthur`. |
| `python package: <name>` | A required pip package isn't installed -- re-run `pip install -r requirements.txt`. |
| NVD API reachability | Can't reach the public NVD CVE database -- the correlate agent's known-CVE lookups will be skipped for that run (not fatal; everything else still works). Only checked when network checks are enabled. |

---

## Target scope

The target field (CLI env var `TARGET_ORIGIN`, or the web UI's "Target"
box) accepts **any** domain, subdomain, or IP address -- with or without
a scheme, with or without a port. It's not hardcoded to a lab address.
You can point it at a locally hosted lab app or at a site of your own
that's already publicly reachable. Scanning anything you don't own or
don't have explicit written authorization to test is against the law in
most jurisdictions and is out of scope for this tool -- that's the reason
for the one required checkbox on the scan form.

## Troubleshooting

- **`sudo ./setup.sh` says "Permission denied"** -- make it executable
  first: `chmod +x setup.sh`.
- **`apt upgrade`/`dist-upgrade` takes a long time or asks for a lot of
  disk space** -- normal on a machine that hasn't been updated in a
  while; let it finish. If disk space is genuinely too tight, run
  `sudo apt-get clean` first to clear the apt cache, then re-run
  `setup.sh`.
- **A note about a reboot being required appears at the end** -- a
  kernel/libc update was installed; safe to ignore for now, ARTHUR runs
  fine without rebooting, reboot whenever is convenient.
- **apt-get install fails on a package** -- your distro's repos may name
  it differently (e.g. some minimal images need `apt-get update` run
  twice, or a `universe`/`multiverse` repo enabled for `nikto`). Install
  it manually and re-run `setup.sh`; it skips steps that already
  succeeded.
- **Health check still shows nikto/nmap as `[FAIL]` after install** --
  open a new shell (or `hash -r`) so your `PATH` picks up the newly
  installed binaries, then re-check.
- **`pip install` fails on a package** -- make sure `python3-venv` and
  `build-essential` (or your platform's equivalent C toolchain) are
  installed; some dependencies build from source on less common
  platforms.
- **"No systemd init detected" / service step skipped** -- normal
  inside most Docker containers, WSL1, and some minimal VMs, which
  don't run systemd as PID 1. Nothing is broken; just run
  `source .venv/bin/activate && python webui/app.py` manually instead.
- **`arthur.service` installed but `systemctl status arthur` shows
  "failed"** -- check `journalctl -u arthur -n 50` for the actual
  Python traceback; the most common cause is `.env` still missing a
  real `OPENAI_API_KEY` or a port 5000 conflict with another process.
- **Health check shows `nuclei`/`osv-scanner`/`zap.sh` as `[WARN]`
  (not found)** -- expected if `setup.sh` couldn't reach GitHub when it
  ran (no outbound network at install time, or a changed release asset
  name upstream). Re-run `sudo ./setup.sh` once the machine has normal
  internet access -- it retries each one and leaves everything else
  alone. This is never a blocking failure: the VA agent reports each
  missing sub-tool clearly and skips it, the rest of the scan still runs.
- **Health check shows `wapiti` as `[FAIL]` even though `setup.sh`
  reported no errors** -- `wapiti3` installs into `.venv/bin`, not a
  system directory, so it's only found by something that has `.venv/bin`
  on its `PATH`. `arthur.service`'s unit file sets this correctly; if
  you're running the web UI manually, make sure you `source
  .venv/bin/activate` first rather than calling `.venv/bin/python
  webui/app.py` from outside the venv.
