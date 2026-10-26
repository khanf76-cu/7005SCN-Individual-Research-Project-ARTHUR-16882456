"""Live CVE lookup against the NVD public API.

This is the one tool in the artefact that is allowed to reach the open
internet rather than the authorized target -- it's a read-only query
against a public vulnerability database (NIST's National Vulnerability
Database), keyed on the product/version strings nmap already detected.
It never sends target data anywhere; it only sends a product name and
version string to look up publicly known CVEs for it.

Rate limiting: NVD's public API (no API key) allows ~5 requests per
rolling 30s window. This tool enforces a minimum delay between calls and
caches results in-process for the run so the same product/version isn't
looked up twice. Set NVD_API_KEY in .env for a higher rate limit if you
have one (free to request from NVD).
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import requests

NVD_BASE_URL = "https://services.nvd.nih.gov/rest/json/cves/2.0"
MIN_DELAY_S = 6.0  # keeps well under the unauthenticated 5-req/30s limit


@dataclass
class CveRecord:
    cve_id: str
    description: str
    cvss_v3_score: float | None
    severity: str | None
    published: str | None


@dataclass
class CveLookupResult:
    query: str
    records: list[CveRecord] = field(default_factory=list)
    error: str | None = None


class CveLookupClient:
    """Stateful so it can enforce rate limiting and caching across many
    lookups within one correlate-agent run."""

    def __init__(self, timeout_s: float = 10.0):
        self._last_call = 0.0
        self._cache: dict[str, CveLookupResult] = {}
        self._timeout_s = timeout_s
        self._api_key = os.environ.get("NVD_API_KEY", "").strip() or None

    def lookup(self, product: str, version: str | None = None, max_results: int = 5) -> CveLookupResult:
        query = f"{product} {version}".strip() if version else product
        if query in self._cache:
            return self._cache[query]

        elapsed = time.time() - self._last_call
        if elapsed < MIN_DELAY_S:
            time.sleep(MIN_DELAY_S - elapsed)

        headers = {"apiKey": self._api_key} if self._api_key else {}
        params = {"keywordSearch": query, "resultsPerPage": max_results}

        try:
            resp = requests.get(
                NVD_BASE_URL, params=params, headers=headers, timeout=self._timeout_s
            )
            self._last_call = time.time()
            if resp.status_code != 200:
                result = CveLookupResult(
                    query=query, error=f"NVD API returned HTTP {resp.status_code}"
                )
                self._cache[query] = result
                return result

            data = resp.json()
            records = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
                )

                score = None
                severity = None
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        score = cvss_data.get("baseScore")
                        severity = metrics[key][0].get("baseSeverity") or cvss_data.get(
                            "baseSeverity"
                        )
                        break

                records.append(
                    CveRecord(
                        cve_id=cve_id,
                        description=description[:500],
                        cvss_v3_score=score,
                        severity=severity,
                        published=cve.get("published"),
                    )
                )

            result = CveLookupResult(query=query, records=records)
        except (requests.RequestException, ValueError) as exc:
            self._last_call = time.time()
            result = CveLookupResult(query=query, error=str(exc))

        self._cache[query] = result
        return result
