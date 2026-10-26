# Common False-Positive Patterns in Automated Scanning

Automated scanners (directory brute-forcers, nikto, nmap NSE scripts)
produce signals that need human- or LLM-level judgement to triage
correctly. Recurring false-positive patterns to check for before
confirming a finding:

- **Soft-404 pages**: a single-page application or misconfigured server
  returns HTTP 200 for every path, including nonexistent ones, often
  with the same body as the real 404 page. A directory brute-force hit
  is only meaningful if its response differs from a baseline request to
  a definitely-nonexistent path.
- **WAF/filter rejection mistaken for a vulnerability**: a 403 or 406
  response to an XSS/SQLi-style payload usually means the payload was
  blocked, not that the underlying class of vulnerability exists.
- **Generic error pages**: a 500 response is only an information-
  disclosure finding if the body actually contains a stack trace,
  internal path, or similar implementation detail — not every 500 is a
  disclosure.
- **Stale NSE script matches**: some nmap vuln scripts flag a service
  version as vulnerable based on a banner match alone, without
  confirming the vulnerable code path is reachable. Treat a script hit
  with no "VULNERABLE" marker or no CVE as a lead to check, not a
  confirmed finding.

Findings should be downgraded to "suspected" whenever one of the above
applies, with the specific reason stated.
