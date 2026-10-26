# Information Disclosure via Error Messages / Stack Traces

Applications that return raw stack traces, framework debug pages, or
internal file paths in HTTP error responses leak implementation details
useful for further attacks (library versions for known-CVE lookups,
internal path structure, sometimes database schema fragments). A 500
response is only a confirmed information-disclosure finding when the
body actually contains such detail — a generic "Internal Server Error"
with no stack trace is not the same finding. When confirming, capture
the exact endpoint, method, and a hash of the response body so the
finding can be independently re-verified rather than trusted on
narrative alone.

Severity is typically low-to-medium on its own (it reveals rather than
directly compromises), but it should be reported because it commonly
accelerates a follow-on attack.
