"""Salida del CLI: resumen en texto para personas y JSON para scripts."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import click

from .flow import Outcome
from .summary import EXIT_CRITICAL, EXIT_FINDINGS, EXIT_OK, SEVERITIES, Summary

SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
STATUS_LABELS = {"COMPLIANT": "cumple", "NON_COMPLIANT": "no cumple", "REQUIRES_REVIEW": "requiere revisión"}
MAX_FINDINGS_LISTED = 20


def render_text(outcome: Outcome, summary: Summary, *, exit_code: int, real_exit_code: int,
                fail_on_severity: str, dry_run: bool, server: str, color: bool) -> str:
    def style(text: str, **kw: Any) -> str:
        return click.style(text, **kw) if color else text

    lines: List[str] = ["", style("Resultado del análisis de SegSoft", bold=True)]
    lines.append(f"  Análisis:      {outcome.analysis_id}")
    if summary.compliance_percentage is not None:
        lines.append(f"  Cumplimiento:  {summary.compliance_percentage:.1f}%"
                     + (f" (ponderado {summary.weighted_compliance_percentage:.1f}%)"
                        if summary.weighted_compliance_percentage is not None else ""))
    lines.append(f"  Hallazgos:     {summary.total_findings}")

    lines += ["", style("Hallazgos por severidad", bold=True)]
    for severity in SEVERITIES:
        count = summary.by_severity.get(severity, 0)
        label = f"  {severity:<9}{count:>5}"
        lines.append(style(label, fg=SEVERITY_COLORS[severity]) if count else label)

    if summary.by_category:
        lines += ["", style("Hallazgos por categoría", bold=True)]
        lines += [f"  {category:<28}{count:>5}" for category, count in summary.by_category.items()]

    if summary.policies:
        lines += ["", style("Políticas", bold=True)]
        for status in ("NON_COMPLIANT", "REQUIRES_REVIEW", "COMPLIANT"):
            group = summary.policies_with(status)
            if group:
                lines.append(f"  {STATUS_LABELS[status]}: {len(group)}")
                if status != "COMPLIANT":
                    lines += [f"    - {p.name} ({p.findings} hallazgos)" for p in group]

    if summary.findings:
        lines += ["", style("Hallazgos", bold=True)]
        for f in summary.findings[:MAX_FINDINGS_LISTED]:
            location = f.get("filePath") or "?"
            if f.get("lineNumber"):
                location += f":{f['lineNumber']}"
            severity = str(f.get("severity"))
            lines.append(f"  {style(f'[{severity}]', fg=SEVERITY_COLORS.get(severity))} {location} "
                         f"- {f.get('policyName') or f.get('category')}")
        if len(summary.findings) > MAX_FINDINGS_LISTED:
            lines.append(f"  ... y {len(summary.findings) - MAX_FINDINGS_LISTED} más. "
                         f"Detalle completo en {server.rstrip('/')}, sección Análisis.")

    if summary.rule_execution_errors:
        lines += ["", style(f"Aviso: {summary.rule_execution_errors} regla(s) no se pudieron ejecutar; "
                            f"el resultado puede estar incompleto.", fg="yellow")]

    lines += ["", _verdict(real_exit_code, fail_on_severity, style)]
    if dry_run and real_exit_code != EXIT_OK:
        lines.append(style(f"DRY-RUN: el código de salida real sería {real_exit_code}; se devuelve {exit_code}.",
                           fg="yellow", bold=True))
    return "\n".join(lines)


def _verdict(code: int, threshold: str, style: Any) -> str:
    if code == EXIT_OK:
        return style(f"OK: no hay hallazgos de severidad {threshold} o superior (exit code 0).", fg="green", bold=True)
    if code == EXIT_CRITICAL:
        return style("FALLA: hay hallazgos CRITICAL (exit code 2).", fg="red", bold=True)
    if code == EXIT_FINDINGS:
        return style(f"FALLA: hay hallazgos de severidad {threshold} o superior (exit code 1).", fg="red", bold=True)
    return style(f"exit code {code}", bold=True)


def to_json(outcome: Outcome, summary: Summary, *, exit_code: int, real_exit_code: int,
            fail_on_severity: str, dry_run: bool, sarif_path: Optional[str] = None) -> str:
    document: Dict[str, Any] = {
        "analysisId": outcome.analysis_id,
        "repositoryId": outcome.repository_id,
        "status": summary.analysis_status,
        "compliancePercentage": summary.compliance_percentage,
        "weightedCompliancePercentage": summary.weighted_compliance_percentage,
        "totalFindings": summary.total_findings,
        "findingsBySeverity": summary.by_severity,
        "findingsByCategory": summary.by_category,
        "policies": [{"name": p.name, "status": p.status, "findings": p.findings} for p in summary.policies],
        "ruleExecutionErrors": summary.rule_execution_errors,
        "failOnSeverity": fail_on_severity,
        "dryRun": dry_run,
        "exitCode": exit_code,
        "findings": [_finding(f) for f in summary.findings],
    }
    if dry_run:
        document["wouldExitWith"] = real_exit_code
    if sarif_path:
        document["sarifPath"] = sarif_path
    return json.dumps(document, ensure_ascii=False, indent=2)


def error_json(message: str, exit_code: int) -> str:
    return json.dumps({"error": message, "exitCode": exit_code}, ensure_ascii=False, indent=2)


def _finding(f: Any) -> Dict[str, Any]:
    keys = ("severity", "category", "policyName", "filePath", "lineNumber", "cweId", "suggestedAction")
    return {k: f.get(k) for k in keys}
