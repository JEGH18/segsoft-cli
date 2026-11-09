"""Lectura y validación de .pdgseg.yml (schemaVersion 1)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .errors import ConfigError

CONFIG_FILE_NAME = ".pdgseg.yml"
SERVER_ENV = "PDGSEG_SERVER_URL"
SEVERITY_THRESHOLDS = ("medium", "high", "critical")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def load_schema() -> Dict[str, Any]:
    text = files("pdgseg").joinpath("schema/pdgseg.schema.v1.json").read_text(encoding="utf-8")
    return json.loads(text)


@dataclass(frozen=True)
class PolicySource:
    """Exactamente una de las tres formas de elegir las políticas."""

    policy_set: Optional[str] = None
    policies: Tuple[str, ...] = ()
    framework: Optional[str] = None

    def describe(self) -> str:
        if self.policy_set:
            return f"Policy Set «{self.policy_set}»"
        if self.framework:
            return f"framework {self.framework}"
        return f"{len(self.policies)} políticas"


@dataclass(frozen=True)
class Config:
    server: str
    policy_source: PolicySource
    fail_on_severity: str = "high"
    exclude: Tuple[str, ...] = ()
    timeout_minutes: int = 15
    poll_interval_seconds: int = 5
    path: Optional[Path] = field(default=None, compare=False)


def load_config(path: Path, server_override: Optional[str] = None,
                env: Optional[Mapping[str, str]] = None) -> Config:
    """Lee, valida y construye la configuración. Cualquier problema es un ConfigError (exit code 10)."""
    env = os.environ if env is None else env
    if not path.is_file():
        raise ConfigError(
            f"No se encontró {path}. Créalo con «pdgseg init» en la raíz del proyecto (genera uno que "
            f"funciona sin editarlo) o indica otro archivo con --config.")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} no es YAML válido: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"No se pudo leer {path}: {e}") from e

    if raw is None:
        raise ConfigError(f"{path} está vacío.")
    return parse_config(raw, path=path, server_override=server_override or env.get(SERVER_ENV))


def parse_config(raw: Any, path: Optional[Path] = None, server_override: Optional[str] = None) -> Config:
    where = str(path) if path else CONFIG_FILE_NAME
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} debe ser un objeto YAML (clave: valor), no {_type_name(raw)}.")

    errors = sorted(Draft202012Validator(load_schema()).iter_errors(raw), key=lambda e: list(e.absolute_path))
    if errors:
        details = "\n".join(f"  - {_describe(e)}" for e in errors)
        raise ConfigError(f"{where} no es válido:\n{details}")

    sources = [k for k in ("policySet", "policies", "framework") if k in raw]
    if len(sources) != 1:
        found = ", ".join(sources) if sources else "ninguna"
        raise ConfigError(
            f"{where} no es válido:\n  - indica exactamente una forma de elegir las políticas: "
            f"policySet, policies o framework (encontradas: {found}).")

    server = (server_override or raw.get("server") or "").strip()
    if not server:
        raise ConfigError(
            f"{where} no es válido:\n  - falta «server» (la URL del backend de SegSoft); "
            f"también se puede dar con la variable {SERVER_ENV} o con --server.")
    _require_secure_server(server, where)

    return Config(
        server=server.rstrip("/"),
        policy_source=PolicySource(
            policy_set=raw.get("policySet"),
            policies=tuple(raw.get("policies", ())),
            framework=raw.get("framework"),
        ),
        fail_on_severity=raw.get("failOnSeverity", "high"),
        exclude=tuple(raw.get("exclude", ())),
        timeout_minutes=raw.get("timeoutMinutes", 15),
        poll_interval_seconds=raw.get("pollIntervalSeconds", 5),
        path=path,
    )


def _require_secure_server(server: str, where: str) -> None:
    parsed = urlparse(server)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"{where} no es válido:\n  - server: «{server}» no es una URL http(s).")
    if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HOSTS:
        raise ConfigError(
            f"{where} no es válido:\n  - server: usa https. El token viaja en cada petición; "
            f"http solo se acepta para localhost.")


def _describe(error: ValidationError) -> str:
    """Un error del schema en una línea, nombrando el campo."""
    location = ".".join(str(p) for p in error.absolute_path) or "(raíz)"
    v = error.validator
    if v == "required":
        missing = error.message.split("'")[1] if "'" in error.message else error.message
        return f"falta el campo obligatorio «{missing}»"
    if v == "additionalProperties":
        extra = sorted(set(error.instance) - set(error.schema.get("properties", {})))
        allowed = ", ".join(error.schema.get("properties", {}))
        return f"campo desconocido «{', '.join(extra)}»; los permitidos son: {allowed}"
    if v == "const":
        return f"{location}: debe ser {error.validator_value!r} (se encontró {error.instance!r})"
    if v == "enum":
        options = ", ".join(str(o) for o in error.validator_value)
        return f"{location}: «{error.instance}» no es válido; usa uno de: {options}"
    if v == "type":
        return f"{location}: debe ser {_schema_type(error.validator_value)}, no {_type_name(error.instance)}"
    if v in ("minimum", "maximum"):
        word = "al menos" if v == "minimum" else "como máximo"
        return f"{location}: debe ser {word} {error.validator_value} (se encontró {error.instance})"
    if v == "pattern":
        if location == "server":
            return f"server: «{error.instance}» no es una URL http(s)"
        return f"{location}: «{error.instance}» no es un id válido (UUID)"
    if v == "minItems":
        return f"{location}: no puede estar vacío"
    if v == "minLength":
        return f"{location}: no puede estar vacío"
    if v == "uniqueItems":
        return f"{location}: tiene elementos repetidos"
    return f"{location}: {error.message}"


_TYPE_NAMES = {"string": "un texto", "integer": "un número entero", "array": "una lista",
               "object": "un objeto", "boolean": "true o false", "number": "un número"}


def _schema_type(t: Any) -> str:
    return _TYPE_NAMES.get(t, str(t)) if isinstance(t, str) else " o ".join(_TYPE_NAMES.get(x, x) for x in t)


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "true/false"
    if isinstance(value, int):
        return "un número"
    if isinstance(value, float):
        return "un número decimal"
    if isinstance(value, str):
        return "un texto"
    if isinstance(value, list):
        return "una lista"
    if isinstance(value, dict):
        return "un objeto"
    return "nada" if value is None else type(value).__name__


def example_config() -> str:
    """What «pdgseg init» writes: valid as is (a framework always exists), with the options commented."""
    return """\
# Configuración de pdgseg (https://github.com/JEGH18/segsoft-cli#configuración-pdgsegyml)
schemaVersion: 1
server: https://segsoft-icesi.westus3.cloudapp.azure.com

# Qué políticas aplicar: deja exactamente UNA de estas tres opciones.
#   framework: todas las políticas activas de un framework. Valores: OWASP_TOP_10_2021, ISO_27001,
#              OWASP_ASVS, NIST_SP_800_53, DEVSECOPS, CUSTOM
#   policySet: un Policy Set de SegSoft, por nombre o id    (ej.: policySet: "Perfil PDG ICESI")
#   policies:  ids de políticas concretas                   (ej.: policies: ["<id>", "<id>"])
framework: OWASP_TOP_10_2021

# Severidad mínima que hace fallar: medium | high | critical (exit code 1, o 2 si hay CRITICAL).
failOnSeverity: high

# Lo que no se sube, además de .git/, node_modules/, entornos virtuales y cachés.
exclude: ["dist/", "build/", "target/"]
"""


__all__: List[str] = ["Config", "PolicySource", "load_config", "parse_config", "CONFIG_FILE_NAME",
                      "SERVER_ENV", "SEVERITY_THRESHOLDS", "example_config"]
