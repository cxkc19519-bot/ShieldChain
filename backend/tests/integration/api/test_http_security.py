from fastapi.testclient import TestClient

from shieldchain.core.config import Settings
from shieldchain.main import create_app


def test_security_headers_apply_to_success_and_public_errors() -> None:
    with TestClient(create_app()) as client:
        for response in (
            client.get("/api/v1/health/live"),
            client.get("/api/v1/does-not-exist"),
        ):
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["content-security-policy"] == (
                "default-src 'none'; frame-ancestors 'none'"
            )
            assert response.headers["permissions-policy"] == (
                "camera=(), geolocation=(), microphone=()"
            )
            assert response.headers["referrer-policy"] == "no-referrer"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["x-frame-options"] == "DENY"
            assert "strict-transport-security" not in response.headers


def test_production_adds_hsts_without_changing_public_health_contract() -> None:
    settings = Settings(_env_file=None, environment="production")
    with TestClient(create_app(settings=settings)) as client:
        response = client.get("/api/v1/health/live")
    assert response.status_code == 200 and response.json() == {"status": "ok"}
    assert response.headers["strict-transport-security"] == ("max-age=31536000; includeSubDomains")


def test_untrusted_host_is_rejected_before_routing() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health/live", headers={"host": "attacker.invalid"})
    assert response.status_code == 400
    assert response.text == "Invalid host header"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_cors_allows_only_configured_origin_and_exposes_request_id() -> None:
    with TestClient(create_app()) as client:
        allowed = client.options(
            "/api/v1/health/live",
            headers={
                "origin": "http://127.0.0.1:5173",
                "access-control-request-method": "GET",
            },
        )
        denied = client.options(
            "/api/v1/health/live",
            headers={
                "origin": "https://attacker.invalid",
                "access-control-request-method": "GET",
            },
        )
        actual = client.get(
            "/api/v1/health/live",
            headers={"origin": "http://127.0.0.1:5173"},
        )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers
    assert actual.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
    assert actual.headers["access-control-expose-headers"] == "X-Request-ID"


def test_declared_request_size_fails_closed_with_stable_public_error() -> None:
    settings = Settings(_env_file=None, http_max_request_bytes=1024)
    with TestClient(create_app(settings=settings)) as client:
        response = client.post(
            "/api/v1/incidents/investigations",
            content=b"{}",
            headers={"content-length": "1025", "x-request-id": "req-size"},
        )
    assert response.status_code == 413
    assert response.json() == {
        "error": {
            "code": "request_too_large",
            "message": "Request exceeds configured limit",
            "request_id": "req-size",
        }
    }
    assert response.headers["x-request-id"] == "req-size"


def test_invalid_content_length_is_minimal_and_does_not_echo_input() -> None:
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/incidents/investigations",
            content=b"{}",
            headers={"content-length": "secret-invalid", "x-request-id": "req-invalid"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_content_length"
    assert "secret-invalid" not in response.text
