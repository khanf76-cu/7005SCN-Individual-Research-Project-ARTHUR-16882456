# Weak / Default Credentials

Test authentication endpoints only with credentials you have been
explicitly authorized to try (e.g. a documented test account, or a
small authorized list for an intentionally-vulnerable training target
like OWASP Juice Shop). Never brute-force a production system or a
third-party service. A successful login with a documented weak/default
credential is confirmed by observing an authenticated session
(response status, session cookie, or redirect to an authenticated
page) — not merely a 200 status, since some apps return 200 on both
success and failure pages.
