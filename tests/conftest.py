from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import responses

SERVER = "https://segsoft.test"
TOKEN = "pdgseg_testtoken0123456789abcdefghijklmnopqrstuv"
REPO_ID = "11111111-1111-1111-1111-111111111111"
ANALYSIS_ID = "22222222-2222-2222-2222-222222222222"
POLICY_SET_ID = "33333333-3333-3333-3333-333333333333"


@pytest.fixture(autouse=True)
def no_real_sleep(monkeypatch):
    """Retries and polling never wait for real; the requested delays are recorded instead."""
    delays: List[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: delays.append(s))
    return delays


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("PDGSEG_API_TOKEN", "PDGSEG_SERVER_URL", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proyecto"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("password = 'x'\n", encoding="utf-8")
    (root / "src" / "dao.java").write_text("String q = \"SELECT\" + id;\n", encoding="utf-8")
    (root / "node_modules" / "lib").mkdir(parents=True)
    (root / "node_modules" / "lib" / "index.js").write_text("x", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    write_config(root)
    return root


def write_config(root: Path, **overrides: Any) -> Path:
    config: Dict[str, Any] = {"schemaVersion": 1, "server": SERVER, "policySet": "Perfil PDG ICESI"}
    config.update(overrides)
    config = {k: v for k, v in config.items() if v is not None}
    path = root / ".pdgseg.yml"
    path.write_text(json.dumps(config), encoding="utf-8")  # JSON is valid YAML
    return path


def finding(severity: str, category: str = "SQL_INJECTION", path: str = "src/dao.java", line: int = 1,
            policy: str = "Consultas parametrizadas") -> Dict[str, Any]:
    return {"id": "f-" + severity + path + str(line), "severity": severity, "category": category,
            "filePath": path, "lineNumber": line, "policyName": policy, "cweId": "CWE-89",
            "suggestedAction": "Usar consultas parametrizadas"}


def results(findings: List[Dict[str, Any]], policy_status: Optional[str] = None) -> Dict[str, Any]:
    status = policy_status or ("NON_COMPLIANT" if findings else "COMPLIANT")
    return {
        "analysis": {"id": ANALYSIS_ID, "status": "COMPLETED"},
        "findings": findings,
        "policyResults": [{"policyId": "p1", "policyName": "Consultas parametrizadas", "status": status,
                           "findingsCount": len(findings)}],
        "ruleExecutionErrors": [],
        "compliancePercentage": 100.0 if not findings else 50.0,
        "weightedCompliancePercentage": 100.0 if not findings else 40.0,
        "categoryBreakdown": {},
    }


SARIF = b'{"version":"2.1.0","runs":[]}'


class FakeBackend:
    """Registers the happy path of the API in a responses mock."""

    def __init__(self, rsps: responses.RequestsMock):
        self.rsps = rsps

    def happy_path(self, findings: List[Dict[str, Any]], *, running_polls: int = 1,
                   policy_status: Optional[str] = None) -> "FakeBackend":
        r = self.rsps
        r.get(f"{SERVER}/api/v1/policy-sets", json={"content": [
            {"id": POLICY_SET_ID, "name": "Perfil PDG ICESI", "status": "ACTIVE"},
            {"id": "other", "name": "Perfil PDG ICESI extendido", "status": "ACTIVE"}]})
        r.post(f"{SERVER}/api/v1/repositories", json={"id": REPO_ID, "status": "READY_FOR_ANALYSIS", "fileCount": 3})
        r.post(f"{SERVER}/api/v1/repositories/{REPO_ID}/policy-selection/apply-set", json={"id": "sel"})
        r.post(f"{SERVER}/api/v1/analyses", json={"id": ANALYSIS_ID, "status": "QUEUED"}, status=202)
        for i in range(running_polls):
            r.get(f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}",
                  json={"id": ANALYSIS_ID, "status": "RUNNING", "rulesExecuted": i, "rulesTotal": 4})
        r.get(f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}", json={"id": ANALYSIS_ID, "status": "COMPLETED"})
        r.get(f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}/results", json=results(findings, policy_status))
        r.get(f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}/sarif", body=SARIF,
              content_type="application/sarif+json")
        return self


@pytest.fixture
def backend():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield FakeBackend(rsps)
