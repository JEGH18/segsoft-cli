"""Cliente HTTP del backend de SegSoft: TLS verificado y reintentos con backoff exponencial."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

import requests

from . import __version__
from .errors import ApiError

RETRY_DELAYS: Tuple[float, ...] = (1, 2, 4)
# Gateways that answer while the backend restarts or is unreachable (Caddy, Vercel).
RETRYABLE_STATUSES = {502, 503, 504}
MAX_RETRY_AFTER_SECONDS = 60
TIMEOUT = (10, 120)  # (connect, read) seconds; uploads of large ZIPs need the long read


class ApiClient:
    """
    Envuelve requests.Session. Reintenta, con esperas de 1s, 2s y 4s:
      - fallos de conexión (DNS, conexión rechazada o cortada) en cualquier método: la petición no llegó;
      - timeouts de lectura y respuestas 502/503/504 solo en peticiones idempotentes (GET, DELETE),
        para no duplicar una subida o un análisis que el servidor sí recibió;
      - 429, en cualquier método, esperando lo que indique Retry-After (máximo 60s).
    TLS siempre se verifica (requests usa certifi, o REQUESTS_CA_BUNDLE si está definida).
    """

    def __init__(self, base_url: str, token: str, *, retry_delays: Sequence[float] = RETRY_DELAYS,
                 sleep: Optional[Callable[[float], None]] = None, log: Optional[Callable[[str], None]] = None,
                 session: Optional[requests.Session] = None, timeout: Tuple[float, float] = TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self._retry_delays = tuple(retry_delays)
        self._sleep = sleep or (lambda seconds: time.sleep(seconds))
        self._log = log or (lambda _msg: None)
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.verify = True
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"pdgseg-cli/{__version__}",
        })

    # ---- public API ------------------------------------------------------------------------

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("GET", path, params=params).json()

    def get_bytes(self, path: str) -> bytes:
        return self._request("GET", path, accept="application/sarif+json, application/json").content

    def post_json(self, path: str, body: Any) -> Any:
        response = self._request("POST", path, json=body)
        return response.json() if response.content else None

    def upload(self, path: str, file_path: Path, field: str = "file") -> Any:
        def files() -> Dict[str, Any]:
            return {field: (file_path.name, file_path.open("rb"), "application/zip")}
        return self._request("POST", path, files_factory=files).json()

    def delete(self, path: str) -> None:
        self._request("DELETE", path)

    # ---- internals -------------------------------------------------------------------------

    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                 json: Any = None, files_factory: Optional[Callable[[], Dict[str, Any]]] = None,
                 accept: Optional[str] = None) -> requests.Response:
        url = self.base_url + path
        idempotent = method in ("GET", "HEAD", "DELETE", "PUT")
        headers = {"Accept": accept} if accept else None
        attempts = len(self._retry_delays) + 1

        for attempt in range(1, attempts + 1):
            files = files_factory() if files_factory else None
            try:
                self._log(f"{method} {url}" + (f" (intento {attempt}/{attempts})" if attempt > 1 else ""))
                response = self._session.request(method, url, params=params, json=json, files=files,
                                                 headers=headers, timeout=self._timeout)
            except requests.exceptions.SSLError as e:
                # A certificate problem does not fix itself by retrying.
                raise ApiError(f"No se pudo establecer una conexión segura con {self.base_url}: el certificado "
                               f"TLS no es válido ({_short(e)}).") from e
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                # ConnectTimeout is a ConnectionError (nothing was sent); ReadTimeout is not (it may have been).
                never_reached_server = (isinstance(e, requests.exceptions.ConnectionError)
                                        and not isinstance(e, requests.exceptions.ReadTimeout))
                retryable = never_reached_server or idempotent
                if retryable and attempt < attempts:
                    self._wait(attempt, f"fallo de conexión ({_short(e)})")
                    continue
                raise ApiError(f"No se pudo conectar con {self.base_url} ({method} {path}) después de "
                               f"{attempt} intento(s): {_short(e)}") from e
            finally:
                if files:
                    for value in files.values():
                        handle = value[1] if isinstance(value, tuple) else value
                        if hasattr(handle, "close"):
                            handle.close()

            self._log(f"  -> {response.status_code}")
            if response.status_code == 429 and attempt < attempts:
                self._sleep(_retry_after(response))
                continue
            if response.status_code in RETRYABLE_STATUSES and idempotent and attempt < attempts:
                self._wait(attempt, f"el servidor respondió {response.status_code}")
                continue
            if response.ok:
                return response
            raise _error_for(response, method, path)

        raise AssertionError("unreachable")  # pragma: no cover

    def _wait(self, attempt: int, reason: str) -> None:
        delay = self._retry_delays[attempt - 1]
        self._log(f"  {reason}; reintentando en {delay:g}s")
        self._sleep(delay)


def _error_for(response: requests.Response, method: str, path: str) -> ApiError:
    status = response.status_code
    message = _server_message(response)
    if status == 401:
        return ApiError("El backend rechazó el token (401)" + (f": {message}" if message else "") +
                        ". Revisa PDGSEG_API_TOKEN: debe ser un token de API vigente (pdgseg_...).", status)
    if status == 403:
        return ApiError("Sin permiso para esta operación (403)" + (f": {message}" if message else "."), status)
    if status == 423:
        return ApiError("La cuenta dueña del token está bloqueada (423)" + (f": {message}" if message else "."),
                        status)
    detail = f": {message}" if message else ""
    return ApiError(f"{method} {path} respondió {status}{detail}", status)


def _server_message(response: requests.Response) -> Optional[str]:
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        message = body.get("message") or body.get("error")
        return str(message) if message else None
    return None


def _retry_after(response: requests.Response) -> float:
    try:
        return min(max(float(response.headers.get("Retry-After", "1")), 1), MAX_RETRY_AFTER_SECONDS)
    except ValueError:
        return 1


def _short(error: Exception) -> str:
    text = str(error)
    return text if len(text) <= 200 else text[:200] + "..."
