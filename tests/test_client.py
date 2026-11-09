from pathlib import Path

import pytest
import requests
import responses

from pdgseg import __version__
from pdgseg.client import ApiClient
from pdgseg.errors import ApiError

from conftest import SERVER, TOKEN


@pytest.fixture
def client():
    return ApiClient(SERVER, TOKEN)


@responses.activate
def test_sends_the_token_and_identifies_itself(client):
    responses.get(f"{SERVER}/api/v1/x", json={"ok": True})
    assert client.get_json("/api/v1/x") == {"ok": True}
    sent = responses.calls[0].request.headers
    assert sent["Authorization"] == f"Bearer {TOKEN}"
    assert sent["User-Agent"] == f"pdgseg-cli/{__version__}"


@responses.activate
def test_connection_failures_are_retried_after_1_2_and_4_seconds(client, no_real_sleep):
    for _ in range(3):
        responses.get(f"{SERVER}/api/v1/x", body=requests.exceptions.ConnectionError("conexión rechazada"))
    responses.get(f"{SERVER}/api/v1/x", json={"ok": True})

    assert client.get_json("/api/v1/x") == {"ok": True}
    assert no_real_sleep == [1, 2, 4]
    assert len(responses.calls) == 4


@responses.activate
def test_after_the_last_retry_the_error_is_clear(client, no_real_sleep):
    responses.get(f"{SERVER}/api/v1/x", body=requests.exceptions.ConnectionError("Name or service not known"))

    with pytest.raises(ApiError) as e:
        client.get_json("/api/v1/x")
    assert str(e.value).startswith(f"No se pudo conectar con {SERVER} (GET /api/v1/x) después de 4 intento(s)")
    assert "Name or service not known" in str(e.value)
    assert no_real_sleep == [1, 2, 4]


@responses.activate
def test_a_post_is_retried_when_the_connection_failed(client, no_real_sleep):
    responses.post(f"{SERVER}/api/v1/analyses", body=requests.exceptions.ConnectionError("reset"))
    responses.post(f"{SERVER}/api/v1/analyses", json={"id": "a"})
    assert client.post_json("/api/v1/analyses", {}) == {"id": "a"}
    assert no_real_sleep == [1]


@responses.activate
def test_a_post_is_not_retried_after_a_read_timeout(client, no_real_sleep):
    # The server may already have started the analysis: retrying would start a second one.
    responses.post(f"{SERVER}/api/v1/analyses", body=requests.exceptions.ReadTimeout("read timed out"))
    with pytest.raises(ApiError, match="después de 1 intento"):
        client.post_json("/api/v1/analyses", {})
    assert len(responses.calls) == 1


@responses.activate
def test_gateway_errors_are_retried_only_for_reads(client, no_real_sleep):
    responses.get(f"{SERVER}/api/v1/x", status=503)
    responses.get(f"{SERVER}/api/v1/x", json={"ok": True})
    assert client.get_json("/api/v1/x") == {"ok": True}

    responses.post(f"{SERVER}/api/v1/y", status=503)
    with pytest.raises(ApiError, match="respondió 503"):
        client.post_json("/api/v1/y", {})


@responses.activate
def test_429_waits_what_the_server_asks(client, no_real_sleep):
    responses.get(f"{SERVER}/api/v1/x", status=429, headers={"Retry-After": "7"})
    responses.get(f"{SERVER}/api/v1/x", json={"ok": True})
    assert client.get_json("/api/v1/x") == {"ok": True}
    assert no_real_sleep == [7]


@responses.activate
def test_tls_errors_are_not_retried(client, no_real_sleep):
    responses.get(f"{SERVER}/api/v1/x", body=requests.exceptions.SSLError("certificate verify failed"))
    with pytest.raises(ApiError, match="conexión segura .* certificado TLS no es válido"):
        client.get_json("/api/v1/x")
    assert no_real_sleep == []


def test_tls_verification_is_always_on(client):
    assert client._session.verify is True


@responses.activate
@pytest.mark.parametrize("status, expected", [
    (401, "rechazó el token (401): El token de API no es válido. Revisa PDGSEG_API_TOKEN"),
    (403, "Sin permiso para esta operación (403): El token de API no es válido"),
    (423, "bloqueada (423)"),
    (400, "GET /api/v1/x respondió 400: El token de API no es válido"),
])
def test_http_errors_carry_the_server_message(client, status, expected):
    responses.get(f"{SERVER}/api/v1/x", status=status, json={"message": "El token de API no es válido"})
    with pytest.raises(ApiError) as e:
        client.get_json("/api/v1/x")
    assert expected in str(e.value)
    assert e.value.status == status


@responses.activate
def test_upload_resends_the_file_on_retry(client, tmp_path: Path, no_real_sleep):
    zip_path = tmp_path / "repo.zip"
    zip_path.write_bytes(b"PK-zip")
    responses.post(f"{SERVER}/api/v1/repositories", body=requests.exceptions.ConnectionError("reset"))
    responses.post(f"{SERVER}/api/v1/repositories", json={"id": "r"})

    assert client.upload("/api/v1/repositories", zip_path) == {"id": "r"}
    assert b"PK-zip" in responses.calls[1].request.body
