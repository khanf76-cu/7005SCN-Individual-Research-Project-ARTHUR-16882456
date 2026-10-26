# Correlating Detected Versions with Known CVEs

A service/version string from a scanner (e.g. nmap's `-sV` output) is
only a reliable basis for a CVE match when three things line up:
product name, version number, and the affected version range stated in
the CVE record. A product-name-only match (e.g. "nginx" with no version,
or a version string nmap could not fully determine) should be reported
as a possible/unconfirmed match, not a confirmed vulnerability.

Common pitfalls:
- Vendors sometimes backport security fixes to an older-numbered release
  (common in Linux distributions), so a version number alone can
  overstate risk — a distro-patched "old" version may not be vulnerable.
- A banner can be spoofed, truncated, or generic (e.g. a reverse proxy
  reporting the upstream app's version inaccurately).
- CVE descriptions sometimes cover a narrow configuration or build flag,
  not every deployment of that version.

When correlating, state the match confidence explicitly: "confirmed"
only when the exact version falls within the CVE's stated affected
range and there is no indication of backporting; otherwise "suspected",
with the reasoning given.
