from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_backend_image_is_multistage_pinned_and_non_root() -> None:
    dockerfile = _read("backend/Dockerfile")
    assert dockerfile.count("FROM python:3.14.6-slim-bookworm") == 2
    assert " AS builder" in dockerfile and " AS runtime" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'CMD ["uvicorn", "shieldchain.main:create_app", "--factory"' in dockerfile
    assert "COPY ." not in dockerfile
    assert "latest" not in dockerfile.casefold()
    for forbidden in (".env", "DEEPSEEK_API_KEY", "data/shieldchain.db"):
        assert forbidden not in dockerfile


def test_runtime_lock_contains_mcp_oauth_dependencies() -> None:
    runtime = set(_read("backend/requirements-runtime.lock").splitlines())
    assert {
        "mcp==2.0.0",
        "mcp-types==2.0.0",
        "PyJWT==2.13.0",
        "cryptography==50.0.0",
        "httpx2==2.12.0",
        "jsonschema==4.26.0",
    } <= runtime


def test_frontend_image_is_multistage_non_root_and_has_healthcheck() -> None:
    dockerfile = _read("frontend/Dockerfile")
    assert "FROM node:24-alpine3.22 AS builder" in dockerfile
    assert "FROM nginxinc/nginx-unprivileged:1.29.1-alpine3.22 AS runtime" in dockerfile
    assert "npm ci --no-audit --no-fund" in dockerfile
    assert "USER 101:101" in dockerfile
    assert "HEALTHCHECK" in dockerfile and "/healthz" in dockerfile
    assert "latest" not in dockerfile.casefold()


def test_nginx_is_spa_safe_and_proxies_only_approved_backend_boundaries() -> None:
    nginx = _read("frontend/nginx.conf")
    assert "try_files $uri $uri/ /index.html" in nginx
    assert "location /api/" in nginx and "set $backend_upstream http://backend:8000" in nginx
    assert "location = /mcp" in nginx
    assert "location = /.well-known/oauth-protected-resource/mcp" in nginx
    assert "location ^~ /mcp/" in nginx and "return 404" in nginx
    assert "limit_req_zone $binary_remote_addr zone=mcp_per_ip:10m rate=10r/s" in nginx
    assert "client_max_body_size 256k" in nginx
    assert "proxy_buffering off" in nginx and "proxy_request_buffering off" in nginx
    for header in (
        "Authorization",
        "MCP-Protocol-Version",
        "Mcp-Method",
        "Mcp-Name",
        "X-Request-ID",
    ):
        assert f"proxy_set_header {header}" in nginx
    assert 'proxy_set_header X-Forwarded-For ""' in nginx
    assert "client_max_body_size 26m" in nginx
    for header in (
        "Content-Security-Policy",
        "Permissions-Policy",
        "Referrer-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
    ):
        assert header in nginx


def test_compose_runs_migration_before_healthy_backend_and_frontend() -> None:
    compose = _read("compose.yaml")
    assert "condition: service_completed_successfully" in compose
    assert "condition: service_healthy" in compose
    assert "/api/v1/health/ready" in compose
    assert '"127.0.0.1:8080:8080"' in compose
    assert "shieldchain-data:/var/lib/shieldchain" in compose
    assert "read_only: true" in compose
    assert compose.count("cap_drop:") == 2
    assert compose.count("no-new-privileges:true") == 2
    assert 'user: "10001:10001"' in compose
    assert 'user: "101:101"' in compose
    assert "privileged:" not in compose
    assert "/var/run/docker.sock" not in compose
    for forbidden in ("DEEPSEEK_API_KEY", "api_key", "password", "secret"):
        assert forbidden not in compose.casefold()


def test_docker_context_excludes_secrets_state_and_unneeded_delivery_assets() -> None:
    ignored = set(_read(".dockerignore").splitlines())
    assert {
        ".git",
        ".env",
        ".env.*",
        ".venv",
        "**/node_modules",
        "data",
        "delivery",
        "tests",
        "*.db",
        "*.pdf",
    } <= ignored
