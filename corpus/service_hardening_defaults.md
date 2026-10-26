# Common Service Misconfigurations Worth Flagging

When nmap or recon surfaces an open service, these configuration issues
are worth specifically checking for and are commonly missed by
signature-only scanners:

- **Default/weak credentials** on admin interfaces discovered via
  directory brute-force (e.g. `/admin`, `/console`, `/dashboard`) —
  only test with explicitly authorized credentials, never brute-force
  live.
- **Verbose service banners** that reveal exact build numbers or
  internal hostnames, which aid further reconnaissance even without
  being a vulnerability themselves.
- **Unnecessary exposed services** — a database port (e.g. MySQL 3306,
  MongoDB 27017, Redis 6379) reachable from outside what should be an
  internal network segment is a finding on its own (exposure), separate
  from whether any specific CVE applies to the version running.
- **Missing security headers** on HTTP services (e.g. no
  `Content-Security-Policy`, no `X-Frame-Options`, cookies without
  `Secure`/`HttpOnly`) — low severity individually, but worth listing
  as hardening recommendations in the final report.

These are reported as findings in their own right (category
"misconfiguration" or "hardening"), separate from version-specific CVEs.
