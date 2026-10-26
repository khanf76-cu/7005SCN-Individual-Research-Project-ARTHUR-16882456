"""Score an agent run's reported findings against a ground-truth register.

CSV register format (one row per known case), matching the kind of
register used in your proposal's frozen protocol:

    case_id,category,endpoint,expected_outcome
    GT-POS-FTP-LISTING-001,information_disclosure,/ftp/,positive
    GT-NEG-AUTH-001,access_control,/rest/basket/1,negative

`expected_outcome` is "positive" (a real vulnerability should be found)
or "negative" (a control case that should NOT be flagged).

Matching a reported finding to a register case is done on endpoint
substring + category keyword overlap -- deliberately conservative, so a
vague finding doesn't get auto-credited against a specific case. This
mirrors your proposal's point that untested/ambiguous cases must not be
silently counted as detected or as a verified negative.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class GroundTruthCase:
    case_id: str
    category: str
    endpoint: str
    expected_outcome: str  # "positive" | "negative"


@dataclass
class ScoreResult:
    total_cases: int
    tested_positive: int
    tested_negative: int
    true_positive: int
    false_negative: int
    true_negative: int
    false_positive: int
    untested: int
    per_case: list[dict] = field(default_factory=list)

    def detection_rate(self) -> float | None:
        eligible = self.true_positive + self.false_negative
        if eligible == 0:
            return None
        return self.true_positive / eligible

    def false_positive_rate(self) -> float | None:
        eligible = self.true_negative + self.false_positive
        if eligible == 0:
            return None
        return self.false_positive / eligible

    def to_dict(self) -> dict:
        return {
            "total_cases": self.total_cases,
            "tested_positive": self.tested_positive,
            "tested_negative": self.tested_negative,
            "true_positive": self.true_positive,
            "false_negative": self.false_negative,
            "true_negative": self.true_negative,
            "false_positive": self.false_positive,
            "untested": self.untested,
            "detection_rate": self.detection_rate(),
            "false_positive_rate": self.false_positive_rate(),
            "per_case": self.per_case,
        }


def load_ground_truth(csv_path: Path) -> list[GroundTruthCase]:
    cases = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cases.append(
                GroundTruthCase(
                    case_id=row["case_id"],
                    category=row["category"].strip().lower(),
                    endpoint=row["endpoint"].strip(),
                    expected_outcome=row["expected_outcome"].strip().lower(),
                )
            )
    return cases


def load_findings(findings_path: Path) -> list[dict]:
    """Load findings from a run_manifest-adjacent findings export, or a
    plain JSON list produced by extracting AgentRunResult.findings."""
    data = json.loads(findings_path.read_text())
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unrecognised findings file format: {findings_path}")


def score_run(cases: list[GroundTruthCase], findings: list[dict]) -> ScoreResult:
    confirmed = [f for f in findings if f.get("confidence") == "confirmed"]

    per_case = []
    tp = fn = tn = fp = untested = 0
    tested_pos = tested_neg = 0

    for case in cases:
        matched = _match(case, confirmed)
        if case.expected_outcome == "positive":
            if matched:
                tp += 1
                tested_pos += 1
                outcome = "true_positive"
            else:
                fn += 1
                outcome = "false_negative_or_untested"
        else:  # negative control
            if matched:
                fp += 1
                tested_neg += 1
                outcome = "false_positive"
            else:
                tn += 1
                outcome = "true_negative_or_untested"

        was_tested = matched is not None
        if not was_tested and case.expected_outcome == "positive":
            untested += 1

        per_case.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "endpoint": case.endpoint,
                "expected_outcome": case.expected_outcome,
                "outcome": outcome,
                "matched_finding_title": matched.get("title") if matched else None,
            }
        )

    # Unmatched reported findings that don't correspond to any register
    # case are neither TP nor FP against this register -- they're
    # reported separately so they aren't silently dropped or wrongly
    # credited.
    extra = [
        f for f in confirmed if not any(_match(c, [f]) for c in cases)
    ]

    return ScoreResult(
        total_cases=len(cases),
        tested_positive=tested_pos,
        tested_negative=tested_neg,
        true_positive=tp,
        false_negative=fn,
        true_negative=tn,
        false_positive=fp,
        untested=untested,
        per_case=per_case + [
            {"unregistered_finding": f.get("title"), "endpoint": f.get("endpoint")}
            for f in extra
        ],
    )


def _match(case: GroundTruthCase, findings: list[dict]) -> dict | None:
    for f in findings:
        endpoint = (f.get("endpoint") or f.get("evidence") or "").lower()
        title = (f.get("title") or "").lower()
        if case.endpoint.lower() in endpoint or case.endpoint.lower() in title:
            return f
        if case.category and case.category.replace("_", " ") in title:
            return f
    return None
