import pytest

from pdgseg.summary import exit_code_for, summarize

from conftest import finding, results


def summary_of(*severities):
    return summarize(results([finding(s, line=i) for i, s in enumerate(severities)]))


@pytest.mark.parametrize("severities, threshold, expected", [
    ((), "high", 0),                          # all policies COMPLIANT
    (("LOW", "MEDIUM"), "high", 0),           # only LOW/MEDIUM (REQUIRES_REVIEW) with the default threshold
    (("LOW", "MEDIUM"), "medium", 1),         # ...unless failOnSeverity: medium
    (("LOW",), "medium", 0),                  # LOW never fails
    (("HIGH",), "high", 1),
    (("HIGH", "MEDIUM"), "medium", 1),
    (("HIGH",), "critical", 0),               # failOnSeverity: critical lets HIGH through
    (("CRITICAL",), "high", 2),
    (("CRITICAL", "HIGH", "LOW"), "medium", 2),
    (("CRITICAL",), "critical", 2),
])
def test_exit_codes(severities, threshold, expected):
    assert exit_code_for(summary_of(*severities), threshold) == expected


def test_counts_by_severity_and_category():
    s = summarize(results([
        finding("HIGH", "SQL_INJECTION", line=1),
        finding("HIGH", "XSS", line=2),
        finding("LOW", "XSS", line=3),
    ]))
    assert s.by_severity == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 1}
    assert s.by_category == {"XSS": 2, "SQL_INJECTION": 1}
    assert s.total_findings == 3
    assert s.worst_severity == "HIGH"


def test_findings_are_listed_most_severe_first():
    s = summary_of("LOW", "CRITICAL", "MEDIUM")
    assert [f["severity"] for f in s.findings] == ["CRITICAL", "MEDIUM", "LOW"]


def test_policies_grouped_by_status():
    s = summarize(results([finding("MEDIUM")], policy_status="REQUIRES_REVIEW"))
    assert [p.name for p in s.policies_with("REQUIRES_REVIEW")] == ["Consultas parametrizadas"]
    assert s.compliance_percentage == 50.0
