"""Resumen de los resultados de un análisis y su código de salida."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")  # most severe first
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_THRESHOLD_RANK = {"medium": 2, "high": 3, "critical": 4}

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CRITICAL = 2
EXIT_ERROR = 10


@dataclass(frozen=True)
class PolicyLine:
    name: str
    status: str
    findings: int


@dataclass(frozen=True)
class Summary:
    analysis_status: str
    compliance_percentage: Optional[float]
    weighted_compliance_percentage: Optional[float]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    policies: List[PolicyLine]
    rule_execution_errors: int
    findings: List[Mapping[str, Any]]

    @property
    def total_findings(self) -> int:
        return sum(self.by_severity.values())

    @property
    def worst_severity(self) -> Optional[str]:
        return next((s for s in SEVERITIES if self.by_severity.get(s)), None)

    def policies_with(self, status: str) -> List[PolicyLine]:
        return [p for p in self.policies if p.status == status]


def summarize(results: Mapping[str, Any]) -> Summary:
    """results: la respuesta de GET /api/v1/analyses/{id}/results."""
    findings = list(results.get("findings") or [])
    severities = Counter(str(f.get("severity") or "LOW").upper() for f in findings)
    categories = Counter(str(f.get("category") or "SIN_CATEGORIA") for f in findings)
    policies = [
        PolicyLine(name=p.get("policyName") or str(p.get("policyId")), status=p.get("status") or "?",
                   findings=int(p.get("findingsCount") or 0))
        for p in results.get("policyResults") or []
    ]
    analysis = results.get("analysis") or {}
    return Summary(
        analysis_status=analysis.get("status", "COMPLETED"),
        compliance_percentage=_number(results.get("compliancePercentage")),
        weighted_compliance_percentage=_number(results.get("weightedCompliancePercentage")),
        by_severity={s: severities.get(s, 0) for s in SEVERITIES},
        by_category=dict(sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))),
        policies=policies,
        rule_execution_errors=len(results.get("ruleExecutionErrors") or []),
        findings=sorted(findings, key=lambda f: (-_RANK.get(str(f.get("severity")).upper(), 0),
                                                 str(f.get("filePath")), f.get("lineNumber") or 0)),
    )


def exit_code_for(summary: Summary, fail_on_severity: str = "high") -> int:
    """
    0  sin hallazgos, o todos por debajo del umbral failOnSeverity;
    2  hay al menos un CRITICAL (y el umbral lo alcanza, cosa que pasa con cualquier umbral);
    1  hay hallazgos en el umbral o por encima, sin CRITICAL.
    Con el umbral por defecto (high): LOW/MEDIUM -> 0, HIGH -> 1, CRITICAL -> 2.
    """
    worst = summary.worst_severity
    if worst is None or _RANK[worst] < _THRESHOLD_RANK[fail_on_severity]:
        return EXIT_OK
    return EXIT_CRITICAL if worst == "CRITICAL" else EXIT_FINDINGS


def _number(value: Any) -> Optional[float]:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None
