from fastapi import Request
from fastapi.testclient import TestClient

from shieldchain.core.logging import configure_logging
from shieldchain.main import create_app


def test_request_log_contains_response_request_id(capsys) -> None:
    app = create_app()
    configure_logging("test")

    with TestClient(app) as client:
        capsys.readouterr()
        response = client.get(
            "/api/v1/health/live",
            headers={"X-Request-ID": "req-log-123"},
        )

    output = capsys.readouterr().out
    assert response.headers["X-Request-ID"] == "req-log-123"
    assert "request_completed" in output
    assert "req-log-123" in output


def test_following_request_log_does_not_inherit_previous_request_id(capsys) -> None:
    app = create_app()
    configure_logging("test")

    with TestClient(app) as client:
        capsys.readouterr()
        client.get(
            "/api/v1/health/live",
            headers={"X-Request-ID": "req-first"},
        )
        first_output = capsys.readouterr().out

        client.get(
            "/api/v1/health/live",
            headers={"X-Request-ID": "req-second"},
        )
        second_output = capsys.readouterr().out

    assert "req-first" in first_output
    assert "req-second" not in first_output
    assert "req-second" in second_output
    assert "req-first" not in second_output


def test_success_after_unhandled_error_does_not_inherit_request_context(capsys) -> None:
    app = create_app()

    @app.get("/api/v1/test-support/unhandled")
    async def raise_unhandled_error() -> None:
        raise RuntimeError("private failure detail")

    @app.get("/api/v1/test-support/request-id")
    async def read_request_id(request: Request) -> dict[str, str]:
        return {"request_id": request.state.request_id}

    configure_logging("test")
    with TestClient(app, raise_server_exceptions=False) as client:
        capsys.readouterr()
        failed = client.get(
            "/api/v1/test-support/unhandled",
            headers={"X-Request-ID": "req-error"},
        )
        failed_output = capsys.readouterr().out
        succeeded = client.get(
            "/api/v1/test-support/request-id",
            headers={"X-Request-ID": "req-after"},
        )
        succeeded_output = capsys.readouterr().out

    assert failed.status_code == 500
    assert failed.headers["X-Request-ID"] == "req-error"
    assert "req-error" in failed_output
    assert "req-after" not in failed_output
    assert succeeded.status_code == 200
    assert succeeded.headers["X-Request-ID"] == "req-after"
    assert succeeded.json() == {"request_id": "req-after"}
    assert "req-after" in succeeded_output
    assert "req-error" not in succeeded_output
