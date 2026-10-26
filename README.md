# ARTHUR — Multi-Agent LLM Pentest Platform (Evaluation Artefact)

A from-scratch Python artefact for 7005SCN (Individual Research Project):
a **four-agent** pipeline (recon → nmap → VA → correlate) that assesses
an authorized target, enriches findings with live CVE data and an
optional RAG layer, and produces a risk-ranked report — plus a black-cyan
web UI to run it and export the result as HTML, JSON, or PDF.

It also still includes the original **single-agent** CLI tool (`cli.py`)
from the earlier milestone of this project: one LLM loop driving nikto +
scoped HTTP, used for the RAG-on/RAG-off repeatable comparison experiment
your methodology section describes. The two are independent entry points
sharing the same underlying tool/evidence/scope code — see "Two entry
points" below.

This is original orchestration/evaluation code written for this project.
It is **not** a fork of an existing agent framework. The two tools it
drives (nikto, nmap) are standard, independently-maintained open-source
scanners — the same way a human tester would drive them, just automated
and correlated.

## ⚠️ Authorized use only

This tool sends real network requests — including an active nikto scan,
an nmap port/service/NSE scan, and directory brute-forcing — to whatever
target you configure. **Only ever point it at a system you own or have
explicit written authorization to test** (e.g. your own OWASP Juice Shop
instance). Every tool call is checked against `RunConfig.is_in_scope()`
(HTTP tools) or `RunConfig.allowed_hosts` (nmap) before it is sent, and
anything outside scope is blocked and logged — but that only enforces
*where* requests go, not whether you were authorized to point it there.
That authorization is your responsibility.

The **correlate agent** also makes outbound calls to the public NVD CVE
database (read-only, product/version lookups only — see
`agent/tools/cve_lookup_tool.py`) and to the OpenAI API. No target data
is sent to NVD; only product/version strings nmap detected.

## Architecture

```
agent/
  config.py          RunConfig + scope-check choke point (build_config_for_target)
  evidence.py         Append-only JSONL evidence logger
  findings.py          Shared Finding schema used by all 4 agents
  rag.py               TF-IDF retrieval over the corpus/ knowledge base
  llm_agent.py          Single-agent loop (original milestone; used by cli.py)
  scorer.py / compare.py   Ground-truth scoring + RAG-off vs RAG-on comparison
  orchestrator.py       Runs recon -> nmap -> va (parallel) -> correlate
  agents/
    recon_agent.py        Wraps 6 recon tools (see below)
    nmap_agent.py          Wraps nmap_tool, flags CVE/VULNERABLE script hits
    va_agent.py             Runs 8 VA sub-tools concurrently (see below)
    correlate_agent.py       Merges all findings, CVE lookups, RAG, GPT-5-mini
  tools/
    dirbrute_tool.py      Scoped path brute-force (baseline-aware)
    subdomain_tool.py      DNS subdomain enum (skipped for literal-IP targets)
    robots_sitemap_tool.py  robots.txt Disallow leads + sitemap.xml URLs
    security_headers_tool.py Missing baseline security response headers
    http_methods_tool.py    OPTIONS probe for risky HTTP methods (PUT/DELETE/TRACE)
    tech_fingerprint_tool.py Header/body-signature CMS & framework fingerprinting
    nmap_tool.py             Scoped nmap -sV + NSE vuln/safe scripts, XML parsing
    nikto_tool.py             Scoped nikto subprocess wrapper (-Format xml)
    tls_tool.py               TLS protocol/certificate hygiene (pure Python ssl/cryptography)
    cookie_tool.py            Session-cookie Secure/HttpOnly/SameSite attribute check
    sqlmap_tool.py            Scoped sqlmap subprocess wrapper (confirmed SQLi)
    wapiti_tool.py            Scoped wapiti3 subprocess wrapper (active input-fuzzing DAST)
    nuclei_tool.py            Scoped nuclei subprocess wrapper (CVE/misconfig templates)
    osv_tool.py               Opportunistic dependency-CVE check via exposed manifests + osv-scanner
    zap_tool.py               Drives an OWASP ZAP daemon via its REST API (spider + active scan)
    http_tool.py               Scoped single HTTP request tool (shared by all recon tools)
    cve_lookup_tool.py         Rate-limited NVD public API client
  wordlists/             Built-in path/subdomain wordlists
corpus/                 RAG knowledge base (9 original docs: vuln classes,
                         CVE-correlation guidance, false-positive patterns)
webui/
  app.py                Flask app: target form, background job, status, exports
  pdf_export.py           fpdf2-based PDF report generator
  templates/               Black-cyan themed Jinja templates
  static/style.css          Theme
tests/                  108 pytest tests, all mocked — no live target/API key needed
cli.py                 Single-agent CLI (run/score/compare) from the earlier milestone
```

### Why this design

- **Single choke point for scope**, reused by every network-capable tool
  (`is_in_scope` for HTTP, `allowed_hosts` membership for nmap), so the
  safety property is enforced and tested in one place
  (`tests/test_config_scope.py`, `tests/test_nmap_tool.py`).
- **Shared `Finding` schema** across all four agents means the correlate
  agent needs no per-agent parsing logic — it just merges four lists.
- **Confidence starts conservative.** Signature/fuzz-based findings
  (nikto, wapiti, nuclei, ZAP alerts below "High" confidence) default to
  `"suspected"`; findings with a direct, version-matched or
  exploit-confirmed basis (sqlmap's confirmed injections, TLS/cookie
  facts read straight off the wire, osv-scanner's version-matched CVEs)
  are `"confirmed"`. nmap script hits are only `"confirmed"` when the
  output explicitly contains a CVE ID or a `VULNERABLE` marker. The
  correlate agent is where confidence is actually adjudicated,
  cross-referencing agents and live CVE data — not any single tool.
- **No single point of failure in VA.** The original design ran one
  scanner (nikto) and, per a real bug this artefact hit and fixed, that
  scanner could fail silently and look like a clean 0-finding scan. VA
  now runs 8 independent sub-tools concurrently and reports a per-tool
  `tool_errors` map, so a scan is never just "trust the one tool that ran".
- **CVE correlation is evidence-gated.** The correlate agent is
  explicitly instructed (and the RAG corpus reinforces) to upgrade
  confidence only when a looked-up CVE's affected version range genuinely
  matches what nmap detected — not on product-name similarity alone.
- **Parallel-but-isolated agent execution.** recon/nmap/va run
  concurrently (they're independent processes against the same target)
  via a thread pool; a failure in one is caught and recorded in
  `errors{}` rather than aborting the whole run, so a nmap permissions
  issue, say, doesn't lose your recon and VA results.
- **Everything is still evidence-logged.** Each agent gets its own
  `evidence.jsonl` under the run's output directory, plus the
  orchestrator's own top-level log — so a marker can trace every tool
  call, CVE lookup, and model call end to end.

## Agent abilities & operations

`recon`, `nmap`, and `va` run **simultaneously** (one thread pool, three
independent agent processes against the same target); `correlate` starts
only once all three finish, since de-duplicating and ranking findings
needs their combined output — it can't meaningfully run before the
others exist. The web UI's live results panel shows each agent's
findings the moment that specific agent finishes, not just at the end
of the whole run.

| Agent | Runs | Operations performed | Output |
|---|---|---|---|
| **recon** | parallel with nmap/va | 6 scoped tools, every request still checked against `is_in_scope()`: **1)** directory/path brute-force against a built-in wordlist, baseline-aware so a 200-everything SPA doesn't flood it with false hits (`dirbrute_tool`); **2)** DNS-based subdomain enumeration via A-record lookups (`subdomain_tool`, skipped automatically when the target is a literal IP); **3)** `robots.txt` Disallow-line + `sitemap.xml` `<loc>` extraction, surfacing paths/URLs the operator pointed a crawler at (`robots_sitemap_tool`); **4)** baseline security response-header audit — HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy (`security_headers_tool`); **5)** OPTIONS probe flagging risky HTTP methods left enabled, e.g. PUT/DELETE/TRACE (`http_methods_tool`); **6)** header + body-signature fingerprinting for common CMSes/frameworks — WordPress, Drupal, Joomla, Django, Laravel, Next.js, Angular, React, Shopify (`tech_fingerprint_tool`) | Hit paths, resolved subdomains, robots/sitemap leads, missing-header list, risky-methods list, detected tech stack, `Finding`s for all of the above |
| **nmap** | parallel with recon/va | `nmap -sT` (TCP connect scan, no root required) for open-port and service/version detection, plus NSE `--script vuln,safe` for vulnerability-detection scripts | Open port count, detected product/version strings, `Finding`s for any NSE hit with a CVE ID or `VULNERABLE` marker |
| **va** | parallel with recon/nmap, and internally runs all 8 of its own sub-tools concurrently too | **1)** `nikto` signature scan (`-Format xml`; see "Known limitations" for why not `json`) (`nikto_tool`); **2)** TLS protocol/certificate hygiene — deprecated protocol versions, expired/self-signed/untrusted certs (`tls_tool`, pure Python, no subprocess); **3)** session-cookie `Secure`/`HttpOnly`/`SameSite` attribute check (`cookie_tool`); **4)** `sqlmap --crawl` for confirmed SQL injection (`sqlmap_tool`); **5)** `wapiti3` active input-fuzzing across XSS/SQLi/SSRF/XXE/CSRF/CRLF/backup-file/exec modules (`wapiti_tool`; SSRF/XXE confirm blind hits via an external OOB callback service, see "Known limitations"); **6)** `nuclei` community CVE/misconfiguration template matching (`nuclei_tool`, best-effort install); **7)** opportunistic dependency-CVE check — probes for an accidentally-exposed `package-lock.json`/`requirements.txt`/etc. and, if found, runs `osv-scanner` against it (`osv_tool`, best-effort install); **8)** OWASP ZAP spider + active scan driven over its local REST API (`zap_tool`, best-effort install) | `Finding`s per sub-tool hit, confidence varies by sub-tool (see above); `tool_errors` map naming any sub-tool that didn't run cleanly (unavailable, errored, or timed out) so a quiet VA stage is never ambiguous |
| **correlate** | last, after the other three | De-duplicates findings that multiple agents independently flagged; looks up each nmap-detected product/version against the public NVD CVE database (read-only, rate-limited, caches per run); retrieves relevant reference material from the RAG corpus; sends everything to GPT-5-mini to assign final severity/confidence and write the executive summary | Final de-duplicated, risk-ranked report — what the web UI renders and exports |

Three of VA's sub-tools (nuclei, osv-scanner, ZAP) aren't apt-packaged;
`setup.sh` downloads each as a prebuilt binary from its GitHub releases,
**best-effort** — if that download fails for any reason (no outbound
network to GitHub at install time, a changed release asset name), that
one sub-tool is skipped on every scan with a clear `tool_errors` entry,
rather than failing the whole install or the whole VA stage. The other
five (nikto, nmap, sqlmap, wapiti, tls/cookie's own Python) are reliably
apt/pip-installed and always run.

Every tool call any agent makes is scope-checked against
`RunConfig.is_in_scope()` (HTTP) or `RunConfig.allowed_hosts` (nmap)
before it is sent, and logged to that agent's `evidence.jsonl` regardless
of outcome.

## Setup

Easiest path — one command fully updates the system (`apt update` /
`upgrade` / `dist-upgrade`), installs everything (nikto, nmap, sqlmap,
the venv + Python packages including wapiti3, best-effort downloads of
nuclei/osv-scanner/OWASP ZAP, scaffolds `.env`, and installs ARTHUR as a
systemd service so the web UI starts automatically and stays running),
then runs a health check:

```bash
sudo ./setup.sh
```

See `INSTALL.md` for exactly what that does, a manual/no-`sudo`
fallback, and how to read the health-check output. Either way, once it's
done, edit `.env` with your real `OPENAI_API_KEY`:

```bash
nano .env
systemctl restart arthur   # only if setup.sh installed the service
```

Both tool wrappers check availability (`nikto_available()`,
`nmap_available()`) and raise a clear error if missing, rather than
failing silently mid-run. nmap runs with `-sT` (TCP connect scan), which
does **not** require root/sudo.

You can re-verify installation at any time with:
```bash
.venv/bin/python -m agent.health
```
or via the web UI's **system health** page.

## Running the multi-agent pipeline

### Web UI (recommended)

```bash
python webui/app.py
# open http://127.0.0.1:5000/
```

Enter the target origin, optionally tick "Enable RAG" and/or "Skip nmap"
(if nmap isn't installed or you lack permissions), and launch. The page
polls stage status live and reloads to show the final report once
`correlate` completes. From there, export to **JSON**, **HTML**
(standalone, styled, shareable), or **PDF**.

### Programmatically / from a script

```python
from pathlib import Path
from agent.config import build_config_for_target
from agent.orchestrator import run_full_assessment

config = build_config_for_target("http://10.15.20.21:3001", rag_enabled=True)
result = run_full_assessment(config, Path("runs/full-1"), corpus_dir=Path("corpus"))
print(result.correlate.executive_summary)
```

Each stage's evidence lands under `runs/full-1/{recon,nmap,va,correlate}/`,
and `runs/full-1/run_manifest.json` records the target, scope, DNS pin,
and RAG setting for the whole run.

## Two entry points: why both exist

- **`cli.py run/score/compare`** — the original single-agent design
  (one LLM loop choosing between nikto and raw HTTP requests each turn).
  Kept because your methodology's RAG-off vs RAG-on repeatable comparison
  experiment (`cli.py compare`) was built and tested against it; it's a
  simpler, more controlled unit for that specific experiment.
- **`webui/` + `orchestrator.py`** — the four-agent pipeline described
  above, which is the main artefact deliverable: broader coverage
  (recon + port/service scanning, not just HTTP), live CVE enrichment,
  and a presentable report.

Both share `config.py`, `evidence.py`, `rag.py`, and the nikto/http tool
wrappers, so the scope-safety and evidence-logging guarantees are
identical in either mode.

## Scoring against a ground-truth register (single-agent CLI)

```bash
cp ground_truth.example.csv ground_truth.csv   # edit with your real cases
python cli.py run --rag off --out runs/e2-r1
python cli.py score --run runs/e2-r1 --ground-truth ground_truth.csv
python cli.py compare --off-dir runs/rag-off --on-dir runs/rag-on
```

## Testing

```bash
pytest tests/ -v
```

108 tests, all against mocked OpenAI/subprocess/HTTP/NVD calls — no API
key, network access, nikto, nmap, sqlmap, wapiti, nuclei, osv-scanner, or
ZAP required to verify the orchestration logic itself. Covers: scope
enforcement, dirbrute baseline filtering, subdomain enum IP-skip logic,
the four new recon tools (robots/sitemap parsing, security-header audit,
HTTP method probing, tech fingerprinting) and the recon agent's wiring of
all six, nikto's `-Format xml` parsing + its DTD self-heal + its
"+ ERROR:" failure detection, the 7 VA sub-tools added for broader
coverage (TLS/cert, cookies, sqlmap, wapiti, nuclei, osv-scanner, ZAP) and
va_agent's concurrent fan-out/error-isolation across all 8, nmap XML
parsing, nmap-agent severity triage, CVE lookup caching/error handling,
correlate-agent merging + malformed-JSON fallback, the single-agent
loop, RAG retrieval, the scorer, the health check (including the OS and
systemd-service checks), and the web UI's routes/exports (including a
real PDF byte check).

## Known limitations (be upfront about these in your report)

- **nikto confidence is heuristic.** `va_agent.py` marks everything
  `"suspected"` until correlate adjudicates; a report that skips
  correlate (or where the LLM call fails) will show nikto findings as
  unconfirmed by design, not by bug.
- **nmap NSE "VULNERABLE" detection is a text-pattern match**
  (`CVE_PATTERN` / the literal string `VULNERABLE`) against script
  output, not a parse of NSE's internal structured results — state this
  as a scoring-methodology limitation.
- **CVE matching is keyword-based** (NVD's own `keywordSearch`), not a
  CPE-exact match, so results can include near-miss products; the
  correlate agent is instructed to filter these, but isn't infallible —
  spot-check the `related_cves` in your final report.
- **Subdomain enumeration only applies to domain targets.** A literal-IP
  target (like a lab Juice Shop instance) will correctly show
  `applicable: false` — this is not a bug, it's recorded as
  not-applicable in both the evidence log and the recon findings.
- **The web UI's job store is in-memory**, single-process. Restarting
  `webui/app.py` loses in-progress job status (though files already
  written under `webui_runs/<job_id>/` are untouched). Fine for
  single-user coursework use; not production-hardened.
- **RAG corpus is small** (9 original documents). Record its document
  count and content in your report's reproducibility section if you
  expand it.
- A **single run per target** gives no measure of run-to-run variation
  for the multi-agent pipeline specifically (the single-agent `cli.py
  compare` path supports repeats; the orchestrator currently does not
  batch repeats automatically) — report this as a threat to validity if
  you only run the pipeline once.
- **nikto uses `-Format xml`, not `json`.** The Debian/Ubuntu `nikto`
  package (2.1.5, as of this writing) doesn't support `-Format json` at
  all (added upstream in 2.1.6); passing it makes nikto print `+ ERROR:
  Invalid output format` and exit instantly with returncode 0, which
  previously made the VA stage silently report "0 findings" as if the
  scan had run cleanly. `nikto_tool.py` now uses `-Format xml` and
  explicitly detects nikto's `"+ ERROR:"` failure pattern (which doesn't
  show up as a nonzero exit code) so a real tool failure is always
  reported, not hidden. XML also needed a second fix: nikto's XML writer
  refuses to run unless it can read a DTD file that minimal/cloud Ubuntu
  images routinely strip via a dpkg doc-stripping policy (a packaging bug
  in nikto's own `.deb`) — both `setup.sh` and `nikto_tool.py` self-heal
  this with a harmless placeholder file, since nikto only checks the
  file's existence/readability and never parses it.
- **OpenVAS/GVM was deliberately left out.** It needs its own Postgres
  database, Redis, two daemons, and a multi-hour vulnerability-feed sync
  before it can scan anything — a different scale of dependency than
  every other tool here, and out of proportion for a coursework
  deliverable. This was a scoped decision, not an oversight; state it as
  such if asked about VA coverage breadth.
- **wapiti's `ssrf`/`xxe` modules rely on an external callback
  service.** Both use a third-party out-of-band service (`wapiti3.ovh`)
  to confirm a blind interaction, meaning a response from the target
  gets relayed to that service rather than staying between ARTHUR and
  the authorized target — a side channel most of this tool's design
  deliberately avoids. They're enabled in `DEFAULT_MODULES` anyway as an
  accepted tradeoff for SSRF/XXE coverage; state this explicitly if
  asked about ARTHUR's scope/data-handling boundaries. Remove
  `"ssrf,xxe"` from `wapiti_tool.py`'s `DEFAULT_MODULES` to go back to
  the fully self-contained module set.
- **sqlmap/wapiti rely on crawling to find parameters to test**, same as
  a human tester starting from the target's homepage. A site with no
  linked, query-parameterised pages (a pure SPA with client-side-only
  routing, say) gives them nothing to crawl to, and they'll legitimately
  report zero findings rather than erroring — not a bug, a structural
  limit of black-box crawling without a sitemap of real endpoints.
- **Running all 8 VA sub-tools concurrently against a small/local target
  can saturate it.** This is by design for a normal-sized target (see
  "Why this design" above), but a lightweight local deployment (a single
  Docker container running e.g. OWASP Juice Shop with no connection-pool
  tuning) can genuinely struggle to serve 8 scanners' worth of concurrent
  traffic plus recon's own crawl plus nmap, on top of its own normal
  resource limits. Symptoms seen in testing: recon taking far longer than
  the same scan against a normally-provisioned remote target, `cookie_tool`
  hitting a connect timeout, and `nikto` producing truncated XML output
  (its `-maxtime` cutoff, or the target simply going unresponsive mid-scan,
  can leave the output file without its closing tags). `cookie_tool`
  retries once on a transient connection failure before giving up, and
  `nikto_tool` recovers whatever complete `<item>` findings it can from a
  truncated document rather than discarding the whole scan over one
  incomplete tag at the end — but if a target is this resource-constrained,
  expect slower/noisier results than against a normally-provisioned one,
  and consider giving it more resources (or running fewer concurrent
  assessments against it) rather than treating a timeout here as a finding
  in itself.
- **nuclei, osv-scanner, and ZAP are best-effort installs.** `setup.sh`
  downloads each from GitHub releases; if that fails for any reason (see
  the Agent abilities table above), that sub-tool is skipped on every
  scan with a clear `tool_errors` entry rather than breaking the install
  or the rest of the VA stage. These three (along with nikto/ZAP's
  network dependency on GitHub at install time) could not be live-tested
  against a real target from inside this development session's sandboxed
  network — unlike nikto, tls, cookies, sqlmap, and wapiti, which were
  all confirmed end-to-end against a deliberately vulnerable local test
  app before this was shipped. Do one supervised scan after deploying
  that specifically checks these three in the live results panel.
- **ZAP's active scan can be refused against a CDN-fronted target.**
  `ascan/action/scan` requires the target URL to already be a node in
  ZAP's internal Sites tree; the spider should populate that, but against
  an unusual front-end (a CDN, a WAF treating ZAP's crawler differently
  from a browser, an aggressive robots.txt) the spider can legitimately
  crawl zero pages, and ZAP's API then rejects the active-scan request
  outright. `zap_tool.py` calls ZAP's `accessUrl` first to force the root
  URL into the Sites tree regardless of what the spider finds, and treats
  spider/ascan failures as non-fatal (`truncated=True`) rather than
  discarding whatever alerts the passive scanner already picked up — so a
  CDN-fronted target gets at least passive-scan coverage from ZAP even
  when the active scan itself can't run.

## AI-assistance disclosure

If you use Claude (or another AI tool) to help write or debug any part
of this code, record that honestly in your dissertation's required AI-use
statement: which tool, which date(s), what you asked for, and what you
changed. Keep a copy of any written permission from your module leader
authorizing AI use beyond the module's amber-category default, since the
assessment brief requires it to be declared either way.
