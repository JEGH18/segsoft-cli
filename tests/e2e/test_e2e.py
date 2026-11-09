"""
Pruebas E2E: el CLI instalado contra un backend de SegSoft real (backend + motor + PostgreSQL).

Se omiten si no está definida PDGSEG_E2E_SERVER_URL. Variables:
  PDGSEG_E2E_SERVER_URL      p. ej. http://localhost:8080
  PDGSEG_E2E_USERNAME/_PASSWORD        cuenta DEVELOPER; con ella se crea (y al final se revoca) un token
  PDGSEG_E2E_ADMIN_USERNAME/_PASSWORD  opcional: SECURITY_ADMIN, para probar «policySet» con un Policy Set propio

Ejecutar:  pytest -m e2e tests/e2e

Los proyectos de tests/e2e/projects disparan reglas de severidad conocida de las políticas sembradas:
  clean    sin hallazgos
  medium   «Control de acceso a datos por rol»                           (SELECT *)        MEDIUM
  high     «Codificación de salida HTML»                                 (innerHTML = x)   HIGH
  critical «Prevención de SQL Injection con consultas parametrizadas»    (executeQuery +)  CRITICAL
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import pytest
import requests

pytestmark = pytest.mark.e2e

SERVER = os.environ.get("PDGSEG_E2E_SERVER_URL", "").rstrip("/")
PROJECTS = Path(__file__).parent / "projects"
POLICY_NAMES = (
    "Control de acceso a datos por rol",
    "Codificación de salida HTML",
    "Prevención de SQL Injection con consultas parametrizadas",
)

if not SERVER:
    pytest.skip("PDGSEG_E2E_SERVER_URL no está definida", allow_module_level=True)


# ---- fixtures -----------------------------------------------------------------------------------

def _login(username_var: str, password_var: str) -> Optional[str]:
    username, password = os.environ.get(username_var), os.environ.get(password_var)
    if not username or not password:
        return None
    response = requests.post(f"{SERVER}/api/v1/auth/login", json={"username": username, "password": password},
                             timeout=30)
    response.raise_for_status()
    return response.json()["accessToken"]


@pytest.fixture(scope="session")
def session_jwt() -> str:
    jwt = _login("PDGSEG_E2E_USERNAME", "PDGSEG_E2E_PASSWORD")
    if not jwt:
        pytest.skip("Faltan PDGSEG_E2E_USERNAME y PDGSEG_E2E_PASSWORD")
    return jwt


def _create_token(jwt: str, name: str) -> Dict[str, str]:
    response = requests.post(f"{SERVER}/api/v1/auth/api-tokens", json={"name": name, "expiresInDays": 1},
                             headers={"Authorization": f"Bearer {jwt}"}, timeout=30)
    assert response.status_code == 201, response.text
    return response.json()


def _revoke(jwt: str, token_id: str) -> None:
    requests.delete(f"{SERVER}/api/v1/auth/api-tokens/{token_id}", headers={"Authorization": f"Bearer {jwt}"},
                    timeout=30)


@pytest.fixture(scope="session")
def api_token(session_jwt: str):
    created = _create_token(session_jwt, f"e2e pdgseg-cli {uuid.uuid4().hex[:8]}")
    yield created["token"]
    _revoke(session_jwt, created["id"])


@pytest.fixture(scope="session")
def policy_ids(api_token: str) -> List[str]:
    """Ids de las tres políticas de severidad conocida, buscadas por nombre con el token de API."""
    page = requests.get(f"{SERVER}/api/v1/policies", params={"status": "ACTIVE", "size": 100},
                        headers={"Authorization": f"Bearer {api_token}"}, timeout=30).json()
    by_name = {p["name"]: p["id"] for p in page["content"]}
    missing = [n for n in POLICY_NAMES if n not in by_name]
    if missing:
        pytest.skip(f"El backend no tiene las políticas sembradas: {missing}")
    return [by_name[n] for n in POLICY_NAMES]


@pytest.fixture
def make_project(tmp_path: Path, policy_ids: List[str]):
    def make(kind: str, **config) -> Path:
        root = tmp_path / kind
        shutil.copytree(PROJECTS / kind, root)
        settings = {"schemaVersion": 1, "server": SERVER, "policies": policy_ids}
        settings.update(config)
        settings = {k: v for k, v in settings.items() if v is not None}
        (root / ".pdgseg.yml").write_text(json.dumps(settings, ensure_ascii=False), encoding="utf-8")
        return root
    return make


def pdgseg(project: Path, *args: str, token: Optional[str]) -> subprocess.CompletedProcess:
    """Ejecuta el CLI instalado como lo haría un pipeline: un proceso aparte, salida capturada en UTF-8."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PDGSEG_")}
    if token:
        env["PDGSEG_API_TOKEN"] = token
    return subprocess.run([sys.executable, "-m", "pdgseg.cli", "analyze", "--path", str(project), *args],
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=600)


# ---- Escenario 1: ejecución básica ---------------------------------------------------------------

def test_basic_run_uploads_analyzes_and_summarizes(make_project, api_token):
    result = pdgseg(make_project("clean"), token=api_token)

    assert result.returncode == 0, result.stderr
    assert "iniciado" in result.stderr and "COMPLETED" in result.stderr
    assert "Hallazgos por severidad" in result.stdout
    assert "OK: no hay hallazgos de severidad high o superior (exit code 0)" in result.stdout


# ---- Escenario 2: códigos de salida -------------------------------------------------------------

@pytest.mark.parametrize("kind, threshold, expected", [
    ("medium", None, 0),         # solo MEDIUM (REQUIRES_REVIEW) con el umbral por defecto
    ("medium", "medium", 1),     # failOnSeverity: medium
    ("high", None, 1),
    ("high", "critical", 0),     # failOnSeverity: critical deja pasar HIGH
    ("critical", None, 2),
])
def test_exit_codes(make_project, api_token, kind, threshold, expected):
    result = pdgseg(make_project(kind, failOnSeverity=threshold), token=api_token)
    assert result.returncode == expected, result.stdout + result.stderr


def test_an_invalid_token_is_a_technical_error(make_project):
    result = pdgseg(make_project("clean"), token="pdgseg_" + "x" * 43)
    assert result.returncode == 10
    assert "rechazó el token (401)" in result.stderr


def test_a_revoked_token_stops_working(make_project, session_jwt):
    created = _create_token(session_jwt, "e2e revocado")
    _revoke(session_jwt, created["id"])
    result = pdgseg(make_project("clean"), token=created["token"])
    assert result.returncode == 10
    assert "venció o fue revocado" in result.stderr


def test_an_invalid_config_is_a_technical_error(make_project, api_token):
    result = pdgseg(make_project("clean", failOnSeverity="low"), token=api_token)
    assert result.returncode == 10
    assert "failOnSeverity" in result.stderr


# ---- Escenario 3: SARIF para GitHub Code Scanning ----------------------------------------------

def test_sarif_output_locates_the_finding_in_the_repository(make_project, api_token, tmp_path):
    target = tmp_path / "results.sarif"
    result = pdgseg(make_project("critical"), "--output", "sarif", "--output-path", str(target), token=api_token)

    assert result.returncode == 2, result.stdout + result.stderr
    sarif = json.loads(target.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["automationDetails"]["id"].startswith("pdg-segsoft/analysis-")
    findings = [r for r in run["results"] if r["level"] == "error"]
    location = findings[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/UserDao.java"
    assert location["region"]["startLine"] == 6


# ---- --dry-run, --output json --quiet y otras formas de elegir políticas ------------------------

def test_dry_run_never_fails_the_pipeline_but_says_so(make_project, api_token):
    result = pdgseg(make_project("critical"), "--dry-run", token=api_token)
    assert result.returncode == 0
    assert "DRY-RUN" in result.stderr
    assert "el código de salida real sería 2" in result.stdout


def test_json_quiet_is_only_json(make_project, api_token):
    result = pdgseg(make_project("high"), "--output", "json", "--quiet", token=api_token)
    document = json.loads(result.stdout)
    assert document["findingsBySeverity"]["HIGH"] == 1
    assert document["findingsByCategory"] == {"XSS": 1}
    assert document["exitCode"] == 1 == result.returncode
    assert result.stderr == ""


def test_framework_selects_its_active_policies(make_project, api_token):
    project = make_project("critical", policies=None, framework="OWASP_TOP_10_2021")
    assert pdgseg(project, token=api_token).returncode == 2


def test_policy_set_by_name(make_project, api_token, policy_ids):
    admin = _login("PDGSEG_E2E_ADMIN_USERNAME", "PDGSEG_E2E_ADMIN_PASSWORD")
    if not admin:
        pytest.skip("Faltan PDGSEG_E2E_ADMIN_USERNAME y PDGSEG_E2E_ADMIN_PASSWORD")
    headers = {"Authorization": f"Bearer {admin}"}
    name = f"E2E pdgseg {uuid.uuid4().hex[:8]}"
    created = requests.post(f"{SERVER}/api/v1/policy-sets", headers=headers, timeout=30,
                            json={"name": name, "description": "Creado por las pruebas E2E del CLI",
                                  "policyIds": policy_ids})
    assert created.status_code == 201, created.text
    try:
        project = make_project("critical", policies=None, policySet=name)
        result = pdgseg(project, token=api_token)
        assert result.returncode == 2, result.stdout + result.stderr
        assert f"Policy Set «{name}»" in result.stderr
    finally:
        requests.delete(f"{SERVER}/api/v1/policy-sets/{created.json()['id']}", headers=headers, timeout=30)
