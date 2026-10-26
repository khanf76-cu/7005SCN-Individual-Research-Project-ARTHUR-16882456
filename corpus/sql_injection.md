# SQL Injection

SQL injection occurs when untrusted input is concatenated into a SQL
query without parameterisation, allowing an attacker to alter the
query's logic. Common indicators during black-box testing: database
error messages returned to the client, unexpected row counts when
boolean payloads (e.g. `' OR '1'='1`) are submitted, and timing
differences when time-based payloads (`SLEEP(5)`) are used.

Typical entry points: login forms, search fields, URL parameters used
directly in WHERE clauses, and REST API filter parameters. Confirmation
requires observing a behavioural change directly attributable to the
injected payload (not just an error page), and ideally extracting a
piece of data that could not otherwise be known. Tools: sqlmap for
automated detection; manual boolean/time-based payloads for
confirmation without a full exploitation chain.
