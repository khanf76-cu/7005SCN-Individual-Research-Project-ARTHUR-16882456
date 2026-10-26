# Exposed Directory Listings / Unauthenticated File Access

Web servers or application routes that serve a directory listing (e.g.
an `/ftp/`-style path returning a file index instead of a 403/404)
without authentication can expose files never meant to be public —
configuration backups, credential stores, internal documents. Confirm
by requesting the path directly and checking the response is a genuine
listing or file (not a generic error page styled to look like one), and
then, where authorized, requesting one listed file to demonstrate
actual unauthorized access — without exfiltrating or retaining
sensitive file contents beyond what's needed as evidence.
