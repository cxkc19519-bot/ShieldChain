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
