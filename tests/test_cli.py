"""«pdgseg analyze» de punta a punta contra una API simulada: los escenarios de la HU."""

import json
import zipfile
from pathlib import Path

import pytest
import requests
from click.testing import CliRunner

from pdgseg.cli import main
from pdgseg.config import load_config

from conftest import ANALYSIS_ID, POLICY_SET_ID, REPO_ID, SARIF, SERVER, TOKEN, finding, write_config


def run(project: Path, *args: str, token: str = TOKEN, **env: str):
    runner = CliRunner(mix_stderr=False) if "mix_stderr" in CliRunner.__init__.__code__.co_varnames else CliRunner()
    environment = {"PDGSEG_API_TOKEN": token} if token else {}
    environment.update(env)
    return runner.invoke(main, ["analyze", "--path", str(project), *args], env=environment)


def stderr_of(result) -> str:
    try:
        return result.stderr
    except ValueError:
        return result.output


# ---- Escenario 1: ejecución básica --------------------------------------------------------------

def test_uploads_selects_the_policy_set_starts_polls_and_summarizes(project, backend):
    backend.happy_path([finding("HIGH"), finding("LOW", "XSS", "src/app.py", 3)], running_polls=2)

    result = run(project)

    calls = [(c.request.method, c.request.url.replace(SERVER, "")) for c in backend.rsps.calls]
    assert calls == [
        ("GET", "/api/v1/policy-sets?search=Perfil+PDG+ICESI&size=100"),
        ("POST", "/api/v1/repositories"),
        ("POST", f"/api/v1/repositories/{REPO_ID}/policy-selection/apply-set"),
        ("POST", "/api/v1/analyses"),
        ("GET", f"/api/v1/analyses/{ANALYSIS_ID}"),
        ("GET", f"/api/v1/analyses/{ANALYSIS_ID}"),
        ("GET", f"/api/v1/analyses/{ANALYSIS_ID}"),
        ("GET", f"/api/v1/analyses/{ANALYSIS_ID}/results"),
    ]
    assert json.loads(backend.rsps.calls[2].request.body) == {"policySetId": POLICY_SET_ID}
    assert json.loads(backend.rsps.calls[3].request.body) == {"repositoryId": REPO_ID}

    out = result.stdout
    assert "Hallazgos por severidad" in out and "HIGH" in out
    assert "Hallazgos por categoría" in out and "SQL_INJECTION" in out and "XSS" in out
    assert "[HIGH] src/dao.java:1" in out
    assert "FALLA: hay hallazgos de severidad high o superior (exit code 1)" in out
    assert "RUNNING: 1/4 reglas" in stderr_of(result)
    assert result.exit_code == 1


def test_the_uploaded_zip_has_the_project_without_git_or_node_modules(project, backend):
    backend.happy_path([])
    run(project)
    upload = backend.rsps.calls[1].request
    body = upload.body if isinstance(upload.body, bytes) else upload.body.read()
    start = body.index(b"PK\x03\x04")
    end = body.rindex(b"PK\x05\x06") + 22
    import io
    with zipfile.ZipFile(io.BytesIO(body[start:end])) as zf:
        assert sorted(zf.namelist()) == [".pdgseg.yml", "src/app.py", "src/dao.java"]


def test_policy_ids_and_frameworks_also_select_policies(project, backend):
    backend.happy_path([])
    ids = ["44444444-4444-4444-4444-444444444444"]
    write_config(project, policySet=None, policies=ids)
    backend.rsps.post(f"{SERVER}/api/v1/repositories/{REPO_ID}/policy-selection", json={"id": "sel"})

    assert run(project).exit_code == 0
    selection = [c for c in backend.rsps.calls if c.request.url.endswith("/policy-selection")]
    assert json.loads(selection[0].request.body) == {"policyIds": ids}


def test_an_unknown_policy_set_fails_before_uploading(project, backend):
    backend.rsps.get(f"{SERVER}/api/v1/policy-sets", json={"content": [{"id": "x", "name": "Otro"}]})
    result = run(project)
    assert result.exit_code == 10
    assert "No hay un Policy Set activo llamado «Perfil PDG ICESI». Parecidos: «Otro»." in stderr_of(result)
    assert all("/repositories" not in c.request.url for c in backend.rsps.calls)


# ---- Escenario 2: códigos de salida ------------------------------------------------------------

@pytest.mark.parametrize("severities, threshold, expected", [
    ([], None, 0),
    (["LOW", "MEDIUM"], None, 0),
    (["LOW", "MEDIUM"], "medium", 1),
    (["HIGH"], None, 1),
    (["CRITICAL", "HIGH"], None, 2),
    (["HIGH"], "critical", 0),
])
def test_exit_codes(project, backend, severities, threshold, expected):
    backend.happy_path([finding(s, line=i) for i, s in enumerate(severities)])
    write_config(project, failOnSeverity=threshold)
    assert run(project).exit_code == expected


def test_missing_token_is_a_technical_error(project, backend):
    result = run(project, token="")
    assert result.exit_code == 10
    assert "Falta el token de API" in stderr_of(result)


def test_invalid_config_is_a_technical_error_naming_the_field(project, backend):
    write_config(project, failOnSeverity="low")
    result = run(project)
    assert result.exit_code == 10
    assert "failOnSeverity: «low» no es válido" in stderr_of(result)


def test_missing_config_is_a_technical_error(tmp_path, backend):
    result = run(tmp_path)
    assert result.exit_code == 10
    assert "No se encontró" in stderr_of(result)


def test_rejected_token_is_a_technical_error(project, backend):
    backend.rsps.get(f"{SERVER}/api/v1/policy-sets", status=401,
                     json={"errorCode": "INVALID_API_TOKEN", "message": "El token de API no es válido, venció o fue revocado."})
    result = run(project)
    assert result.exit_code == 10
    assert "rechazó el token (401)" in stderr_of(result)


def test_unreachable_backend_is_a_technical_error_after_retrying(project, backend, no_real_sleep):
    backend.rsps.get(f"{SERVER}/api/v1/policy-sets", body=requests.exceptions.ConnectionError("Connection refused"))
    result = run(project)
    assert result.exit_code == 10
    assert "después de 4 intento(s)" in stderr_of(result)
    assert no_real_sleep[:3] == [1, 2, 4]


def test_failed_analysis_is_a_technical_error(project, backend):
    backend.happy_path([], running_polls=0)
    backend.rsps.replace(responses_get(), f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}",
                         json={"id": ANALYSIS_ID, "status": "FAILED", "errorMessage": "El motor no respondió"})
    result = run(project)
    assert result.exit_code == 10
    assert "falló: El motor no respondió" in stderr_of(result)


def test_an_analysis_that_never_finishes_times_out_and_is_cancelled(project, backend, monkeypatch):
    backend.happy_path([], running_polls=0)
    backend.rsps.replace(responses_get(), f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}",
                         json={"id": ANALYSIS_ID, "status": "RUNNING", "rulesExecuted": 0, "rulesTotal": 4})
    backend.rsps.delete(f"{SERVER}/api/v1/analyses/{ANALYSIS_ID}", status=204)
    clock = iter(range(0, 10_000, 30))
    monkeypatch.setattr("time.monotonic", lambda: next(clock))
    write_config(project, timeoutMinutes=1)

    result = run(project)
    assert result.exit_code == 10
    assert "no terminó en 1 minutos" in stderr_of(result)
    assert any(c.request.method == "DELETE" for c in backend.rsps.calls)


# ---- Escenario 3: SARIF para GitHub Actions -----------------------------------------------------

def test_sarif_output_writes_the_file_and_keeps_the_exit_code(project, backend, tmp_path):
    backend.happy_path([finding("CRITICAL")])
    target = tmp_path / "out" / "results.sarif"

    result = run(project, "--output", "sarif", "--output-path", str(target))

    assert target.read_bytes() == SARIF
    assert result.exit_code == 2
    assert "FALLA: hay hallazgos CRITICAL (exit code 2)" in result.stdout


# ---- --dry-run y --output json --quiet ---------------------------------------------------------

def test_dry_run_returns_0_with_a_visible_warning(project, backend):
    backend.happy_path([finding("CRITICAL")])
    result = run(project, "--dry-run")
    assert result.exit_code == 0
    assert "DRY-RUN" in stderr_of(result)
    assert "el código de salida real sería 2" in result.stdout


def test_dry_run_still_reports_technical_errors(project, backend):
    result = run(project, "--dry-run", token="")
    assert result.exit_code == 10


def test_json_quiet_prints_only_json(project, backend):
    backend.happy_path([finding("HIGH"), finding("MEDIUM", "XSS", line=2)])

    result = run(project, "--output", "json", "--quiet")

    document = json.loads(result.stdout)
    assert document["analysisId"] == ANALYSIS_ID
    assert document["findingsBySeverity"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0}
    assert document["findingsByCategory"] == {"SQL_INJECTION": 1, "XSS": 1}
    assert document["exitCode"] == 1 and result.exit_code == 1
    assert "\x1b[" not in result.stdout
    assert stderr_of(result) == ""


def test_json_with_dry_run_tells_the_real_exit_code(project, backend):
    backend.happy_path([finding("CRITICAL")])
    document = json.loads(run(project, "--output", "json", "--quiet", "--dry-run").stdout)
    assert document["dryRun"] is True and document["exitCode"] == 0 and document["wouldExitWith"] == 2


def test_json_errors_are_json_too(project, backend):
    result = run(project, "--output", "json", "--quiet", token="")
    document = json.loads(result.stdout)
    assert document["exitCode"] == 10 and result.exit_code == 10
    assert "Falta el token" in document["error"]


def test_quiet_and_verbose_are_exclusive(project):
    assert run(project, "--quiet", "--verbose").exit_code == 2  # click usage error


def test_verbose_logs_each_request(project, backend):
    backend.happy_path([])
    assert f"GET {SERVER}/api/v1/policy-sets" in stderr_of(run(project, "--verbose"))


def test_the_token_never_appears_in_the_output(project, backend):
    backend.happy_path([finding("HIGH")])
    result = run(project, "--verbose")
    assert TOKEN not in result.stdout + stderr_of(result)


def test_init_creates_a_config_that_works_without_editing(tmp_path):
    result = CliRunner().invoke(main, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0

    config = load_config(tmp_path / ".pdgseg.yml", env={})
    assert config.policy_source.framework == "OWASP_TOP_10_2021"
    assert config.server == "https://segsoft-icesi.westus3.cloudapp.azure.com"
    assert config.fail_on_severity == "high"
    assert config.exclude == ("dist/", "build/", "target/")

    # It never overwrites an existing file.
    assert CliRunner().invoke(main, ["init", "--path", str(tmp_path)]).exit_code == 10


def test_without_config_the_error_points_to_init(tmp_path, backend):
    result = run(tmp_path)
    assert result.exit_code == 10
    assert "Créalo con «pdgseg init»" in stderr_of(result)


def responses_get():
    import responses
    return responses.GET
