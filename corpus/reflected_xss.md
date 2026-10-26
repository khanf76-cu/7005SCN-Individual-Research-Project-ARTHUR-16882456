# Reflected Cross-Site Scripting (XSS)

Reflected XSS occurs when a request parameter is echoed back into the
HTML response without adequate output encoding, letting an attacker
craft a URL that executes script in a victim's browser session. Confirm
by submitting a distinctive marker string (not a full script payload on
a target you don't control end-to-end) and checking whether it appears
unescaped in the response body, inside an executable context (not just
inside a safely-encoded attribute or comment). A 4xx/406 response from
a WAF or input filter is evidence the payload was rejected, not evidence
that XSS exists — do not report a blocked payload as a confirmed
finding.
