"""El flujo de «pdgseg analyze» contra la API del backend."""

from __future__ import annotations

import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .client import ApiClient
from .config import Config, PolicySource
from .errors import ApiError, PdgsegError
from .packager import Package, build_zip

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED"}


@dataclass
class Outcome:
    repository_id: str
    analysis_id: str
    package: Package
    results: Dict[str, Any]
    sarif: Optional[bytes] = None


class Progress:
    """Mensajes de avance (a stderr, salvo --quiet). Separado para poder silenciarlo en tests."""

    def __init__(self, emit: Callable[[str], None] = lambda _m: None):
        self.emit = emit

    def __call__(self, message: str) -> None:
        self.emit(message)


def run_analysis(client: ApiClient, config: Config, root: Path, *, want_sarif: bool = False,
                 progress: Optional[Progress] = None, sleep: Optional[Callable[[float], None]] = None,
                 monotonic: Optional[Callable[[], float]] = None) -> Outcome:
    progress = progress or Progress()
    sleep = sleep or (lambda seconds: time.sleep(seconds))
    monotonic = monotonic or (lambda: time.monotonic())

    # Resolve the policies first: a typo in .pdgseg.yml should fail before uploading anything.
    selection = resolve_policies(client, config.policy_source)
    progress(f"Políticas: {config.policy_source.describe()}")

    with tempfile.TemporaryDirectory(prefix="pdgseg-") as tmp:
        package = build_zip(root, Path(tmp) / f"{root.resolve().name or 'repo'}.zip", config.exclude)
        progress(f"Comprimidos {package.file_count} archivos ({package.size_bytes / 1024 / 1024:.1f} MB); subiendo...")
        repository = client.upload("/api/v1/repositories", package.path)

    repository_id = str(repository["id"])
    if repository.get("status") != "READY_FOR_ANALYSIS":
        reason = repository.get("errorMessage") or repository.get("status")
        raise PdgsegError(f"El backend no pudo preparar el proyecto subido: {reason}")
    progress(f"Repositorio {repository_id} listo ({repository.get('fileCount', package.file_count)} archivos).")

    kind, value = selection
    if kind == "set":
        client.post_json(f"/api/v1/repositories/{repository_id}/policy-selection/apply-set", {"policySetId": value})
    else:
        client.post_json(f"/api/v1/repositories/{repository_id}/policy-selection", {"policyIds": value})

    analysis = client.post_json("/api/v1/analyses", {"repositoryId": repository_id})
    analysis_id = str(analysis["id"])
    progress(f"Análisis {analysis_id} iniciado.")

    analysis = _wait_until_done(client, analysis_id, config, progress, sleep, monotonic)
    if analysis["status"] == "FAILED":
        raise PdgsegError(f"El análisis {analysis_id} falló: {analysis.get('errorMessage') or 'sin detalle'}")
    if analysis["status"] == "CANCELLED":
        raise PdgsegError(f"El análisis {analysis_id} fue cancelado.")

    results = client.get_json(f"/api/v1/analyses/{analysis_id}/results")
    sarif = client.get_bytes(f"/api/v1/analyses/{analysis_id}/sarif") if want_sarif else None
    return Outcome(repository_id=repository_id, analysis_id=analysis_id, package=package,
                   results=results, sarif=sarif)


def resolve_policies(client: ApiClient, source: PolicySource) -> Tuple[str, Any]:
    """("set", policySetId) o ("policies", [policyId, ...])."""
    if source.policy_set:
        return "set", _resolve_policy_set(client, source.policy_set)
    if source.framework:
        return "policies", _framework_policies(client, source.framework)
    return "policies", list(source.policies)


def _resolve_policy_set(client: ApiClient, name_or_id: str) -> str:
    if _UUID.match(name_or_id):
        try:
            found = client.get_json(f"/api/v1/policy-sets/{name_or_id}")
        except ApiError as e:
            if e.status == 404:
                raise PdgsegError(f"No existe un Policy Set con id {name_or_id}.") from e
            raise
        if found.get("status") not in (None, "ACTIVE"):
            raise PdgsegError(f"El Policy Set {name_or_id} está {found.get('status')}; usa uno activo.")
        return name_or_id

    page = client.get_json("/api/v1/policy-sets", params={"search": name_or_id, "size": 100})
    candidates: List[Dict[str, Any]] = page.get("content") or []
    exact = [c for c in candidates if str(c.get("name", "")).strip().lower() == name_or_id.strip().lower()]
    if len(exact) == 1:
        return str(exact[0]["id"])
    if len(exact) > 1:
        raise PdgsegError(f"Hay {len(exact)} Policy Sets activos llamados «{name_or_id}»; usa su id en policySet.")
    similar = ", ".join(f"«{c.get('name')}»" for c in candidates[:5])
    hint = f" Parecidos: {similar}." if similar else ""
    raise PdgsegError(f"No hay un Policy Set activo llamado «{name_or_id}».{hint}")


def _framework_policies(client: ApiClient, framework: str) -> List[str]:
    ids: List[str] = []
    page_number = 0
    while True:
        page = client.get_json("/api/v1/policies", params={
            "framework": framework, "status": "ACTIVE", "page": page_number, "size": 100})
        ids.extend(str(p["id"]) for p in page.get("content") or [])
        if page.get("last", True) or page_number + 1 >= int(page.get("totalPages") or 0):
            break
        page_number += 1
    if not ids:
        raise PdgsegError(f"No hay políticas activas del framework {framework}.")
    return ids


def _wait_until_done(client: ApiClient, analysis_id: str, config: Config, progress: Progress,
                     sleep: Callable[[float], None], monotonic: Callable[[], float]) -> Dict[str, Any]:
    deadline = monotonic() + config.timeout_minutes * 60
    last_line = None
    while True:
        analysis = client.get_json(f"/api/v1/analyses/{analysis_id}")
        status = analysis.get("status")
        line = _progress_line(analysis)
        if line != last_line:
            progress(line)
            last_line = line
        if status in TERMINAL_STATUSES:
            return analysis
        if monotonic() >= deadline:
            try:
                client.delete(f"/api/v1/analyses/{analysis_id}")
            except ApiError:
                pass  # the timeout is what matters; a failed cancel just leaves it running
            raise PdgsegError(f"El análisis {analysis_id} no terminó en {config.timeout_minutes} minutos "
                              f"(timeoutMinutes en .pdgseg.yml); se pidió cancelarlo.")
        sleep(config.poll_interval_seconds)


def _progress_line(analysis: Dict[str, Any]) -> str:
    status = analysis.get("status")
    executed, total = analysis.get("rulesExecuted"), analysis.get("rulesTotal")
    if status == "RUNNING" and total:
        return f"  {status}: {executed or 0}/{total} reglas"
    return f"  {status}"
