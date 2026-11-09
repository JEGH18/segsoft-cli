from pathlib import Path

import pytest

from pdgseg.config import load_config, parse_config
from pdgseg.errors import ConfigError

BASE = {"schemaVersion": 1, "server": "https://segsoft.test", "policySet": "Perfil"}


def config(**changes):
    raw = dict(BASE)
    raw.update(changes)
    return {k: v for k, v in raw.items() if v is not None}


def error_of(raw, **kw) -> str:
    with pytest.raises(ConfigError) as e:
        parse_config(raw, **kw)
    return str(e.value)


def test_minimal_config_gets_the_defaults():
    c = parse_config(config())
    assert c.server == "https://segsoft.test"
    assert c.policy_source.policy_set == "Perfil"
    assert c.fail_on_severity == "high"
    assert c.timeout_minutes == 15 and c.poll_interval_seconds == 5
    assert c.exclude == ()


def test_full_config():
    c = parse_config(config(policySet=None, framework="OWASP_TOP_10_2021", failOnSeverity="critical",
                            exclude=["dist/", "*.min.js"], timeoutMinutes=30, pollIntervalSeconds=10,
                            server="https://segsoft.test/"))
    assert c.policy_source.framework == "OWASP_TOP_10_2021"
    assert c.fail_on_severity == "critical"
    assert c.exclude == ("dist/", "*.min.js")
    assert c.server == "https://segsoft.test"


def test_missing_file_explains_how_to_create_it(tmp_path: Path):
    with pytest.raises(ConfigError, match="No se encontró .*Créalo con «pdgseg init»"):
        load_config(tmp_path / ".pdgseg.yml", env={})


def test_invalid_yaml_is_reported(tmp_path: Path):
    path = tmp_path / ".pdgseg.yml"
    path.write_text("schemaVersion: [1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="no es YAML válido"):
        load_config(path, env={})


def test_empty_file_is_reported(tmp_path: Path):
    path = tmp_path / ".pdgseg.yml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ConfigError, match="está vacío"):
        load_config(path, env={})


def test_not_a_mapping():
    assert "debe ser un objeto YAML" in error_of(["schemaVersion", 1])


@pytest.mark.parametrize("raw, expected", [
    (config(schemaVersion=2), "schemaVersion: debe ser 1"),
    ({"server": "https://x.test", "policySet": "p"}, "falta el campo obligatorio «schemaVersion»"),
    (config(failOnSeverity="low"), "failOnSeverity: «low» no es válido; usa uno de: medium, high, critical"),
    (config(timeoutMinutes=0), "timeoutMinutes: debe ser al menos 1"),
    (config(timeoutMinutes="10"), "timeoutMinutes: debe ser un número entero, no un texto"),
    (config(policySet=None, policies=["no-es-uuid"]), "policies.0: «no-es-uuid» no es un id válido"),
    (config(policySet=None, policies=[]), "policies: no puede estar vacío"),
    (config(framework="OWASP"), "framework: «OWASP» no es válido"),
    (config(failOnSeverty="high"), "campo desconocido «failOnSeverty»"),
    (config(server="ftp://x"), "server: «ftp://x» no es una URL http(s)"),
])
def test_invalid_fields_name_the_field_and_the_problem(raw, expected):
    assert expected in error_of(raw)


def test_every_error_is_listed_at_once():
    message = error_of(config(failOnSeverity="low", timeoutMinutes=0))
    assert "failOnSeverity" in message and "timeoutMinutes" in message


@pytest.mark.parametrize("raw, found", [
    (config(policySet=None), "ninguna"),
    (config(framework="ISO_27001"), "policySet, framework"),
])
def test_exactly_one_policy_source(raw, found):
    message = error_of(raw)
    assert "exactamente una forma de elegir las políticas" in message
    assert found in message


def test_server_can_come_from_the_environment(tmp_path: Path):
    path = tmp_path / ".pdgseg.yml"
    path.write_text("schemaVersion: 1\npolicySet: Perfil\n", encoding="utf-8")
    c = load_config(path, env={"PDGSEG_SERVER_URL": "https://otro.test"})
    assert c.server == "https://otro.test"


def test_server_override_wins_over_the_file():
    assert parse_config(config(), server_override="https://ci.test").server == "https://ci.test"


def test_missing_server_mentions_the_alternatives():
    assert "PDGSEG_SERVER_URL" in error_of(config(server=None))


def test_plain_http_is_rejected_except_for_localhost():
    assert "usa https" in error_of(config(server="http://segsoft.test"))
    assert parse_config(config(server="http://localhost:8080")).server == "http://localhost:8080"
