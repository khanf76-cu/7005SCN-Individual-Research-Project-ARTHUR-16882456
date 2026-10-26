from pathlib import Path

from agent.scorer import GroundTruthCase, score_run


def test_confirmed_finding_matches_positive_case_as_true_positive():
    cases = [
        GroundTruthCase("GT-1", "information_disclosure", "/rest/products", "positive"),
    ]
    findings = [
        {
            "title": "Stack trace disclosure",
            "severity": "low",
            "evidence": "GET /rest/products returned a stack trace",
            "confidence": "confirmed",
            "endpoint": "/rest/products",
        }
    ]
    result = score_run(cases, findings)
    assert result.true_positive == 1
    assert result.false_negative == 0
    assert result.detection_rate() == 1.0


def test_missing_finding_for_positive_case_is_false_negative():
    cases = [
        GroundTruthCase("GT-1", "information_disclosure", "/ftp/", "positive"),
    ]
    result = score_run(cases, findings=[])
    assert result.true_positive == 0
    assert result.false_negative == 1
    assert result.detection_rate() == 0.0


def test_negative_control_not_flagged_is_true_negative():
    cases = [
        GroundTruthCase("GT-NEG-1", "access_control", "/rest/basket/1", "negative"),
    ]
    result = score_run(cases, findings=[])
    assert result.true_negative == 1
    assert result.false_positive == 0


def test_negative_control_wrongly_flagged_is_false_positive():
    cases = [
        GroundTruthCase("GT-NEG-1", "access_control", "/rest/basket/1", "negative"),
    ]
    findings = [
        {
            "title": "Broken access control",
            "confidence": "confirmed",
            "endpoint": "/rest/basket/1",
        }
    ]
    result = score_run(cases, findings)
    assert result.false_positive == 1
    assert result.true_negative == 0


def test_suspected_finding_does_not_count_as_confirmed():
    cases = [
        GroundTruthCase("GT-1", "reflected_xss", "/redirect", "positive"),
    ]
    findings = [
        {
            "title": "Possible reflected XSS",
            "confidence": "suspected",
            "endpoint": "/redirect",
        }
    ]
    result = score_run(cases, findings)
    assert result.true_positive == 0
    assert result.false_negative == 1


def test_untested_positive_case_counted_separately_from_false_negative_label():
    cases = [
        GroundTruthCase("GT-1", "weak_credentials", "/rest/user/login", "positive"),
    ]
    result = score_run(cases, findings=[])
    assert result.untested == 1
