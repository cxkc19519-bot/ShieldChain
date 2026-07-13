import re
from collections.abc import Iterator

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from shieldchain.core.errors import ApiError
from shieldchain.main import create_app


@pytest.fixture
def error_client() -> Iterator[TestClient]:
    app = create_app()

    @app.get("/api/v1/test-support/request-id")
    async def read_request_id(request: Request) -> dict[str, str]:
        return {"request_id": request.state.request_id}

    @app.get("/api/v1/test-support/unhandled")
    async def raise_unhandled_error() -> None:
        raise RuntimeError("sensitive test-secret exception detail")

    @app.get("/api/v1/test-support/api-error")
    async def raise_api_error() -> None:
        raise ApiError(code="invalid_input", message="Input is invalid", status_code=422)

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_valid_incoming_request_id_is_preserved(error_client: TestClient) -> None:
    response = error_client.get(
        "/api/v1/test-support/request-id",
        headers={"X-Request-ID": "req-123"},
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "req-123"
    assert response.json() == {"request_id": "req-123"}


def test_missing_request_id_generates_lowercase_hex_uuid(error_client: TestClient) -> None:
    response = error_client.get("/api/v1/test-support/request-id")

    request_id = response.headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{32}", request_id)
    assert response.json() == {"request_id": request_id}


@pytest.mark.parametrize("invalid_request_id", ["contains spaces", "a" * 65])
def test_invalid_request_id_is_replaced(
    error_client: TestClient,
    invalid_request_id: str,
) -> None:
    response = error_client.get(
        "/api/v1/test-support/request-id",
        headers={"X-Request-ID": invalid_request_id},
    )

    request_id = response.headers["X-Request-ID"]
    assert request_id != invalid_request_id
    assert re.fullmatch(r"[0-9a-f]{32}", request_id)
    assert response.json() == {"request_id": request_id}


def test_unhandled_error_is_stable_and_does_not_leak_details(
    error_client: TestClient,
) -> None:
    response = error_client.get(
        "/api/v1/test-support/unhandled",
        headers={"X-Request-ID": "req-123"},
    )

    assert response.status_code == 500
    assert response.headers["X-Request-ID"] == "req-123"
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "Internal server error",
            "request_id": "req-123",
        }
    }
    assert "test-secret" not in response.text
    assert "exception detail" not in response.text


def test_api_error_returns_exact_public_contract(error_client: TestClient) -> None:
    response = error_client.get(
        "/api/v1/test-support/api-error",
        headers={"X-Request-ID": "req.api_123"},
    )

    assert response.status_code == 422
    assert response.headers["X-Request-ID"] == "req.api_123"
    assert response.json() == {
        "error": {
            "code": "invalid_input",
            "message": "Input is invalid",
            "request_id": "req.api_123",
        }
    }
