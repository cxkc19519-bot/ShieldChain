import json
from pathlib import Path

import yaml
from alembic.config import Config
from alembic.script import ScriptDirectory
from packaging.version import Version

from shieldchain.core.version import EXPECTED_SCHEMA_REVISION

ROOT = Path(__file__).resolve().parents[3]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_runtime_readiness_revision_matches_the_single_migration_head() -> None:
    config = Config(str(ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "backend" / "migrations"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert heads == [EXPECTED_SCHEMA_REVISION]
    assert EXPECTED_SCHEMA_REVISION == "20260824_08"


def test_task14_offline_smoke_and_mcp_conformance_are_bounded() -> None:
    conformance = _read("tests/scripts/mcp_conformance.py")
    smoke = _read("tests/scripts/run-task14-smoke.ps1")
    verify = _read("scripts/verify.ps1")
    assert "from mcp import Client" in conformance
    assert "TemporaryDirectory" in conformance
    assert "MCP_CONFORMANCE_TESTED=True" in conformance
    assert "NETWORK_ACCESS_TESTED=False" in conformance
    assert "REAL_DEVICE_PATHS_TESTED=False" in conformance
    for forbidden in ("urlopen", "requests.", "httpx.", "subprocess", "shell=True"):
        assert forbidden not in conformance
    assert "mcp_conformance.py" in smoke
    assert "run-phase8-container-smoke.ps1" in smoke
    assert '$containerArguments += "-StaticOnly"' in smoke
    assert "-ProjectRoot $ProjectRoot -StaticOnly" not in smoke
    assert "run-task14-smoke.ps1" in verify
    assert '"audit", "--prefix"' in verify
    assert '"downgrade", "-1"' in verify


def test_container_and_proxy_contract_keep_production_least_privilege() -> None:
    compose = _read("compose.yaml")
    parsed = yaml.safe_load(compose)
    nginx = _read("frontend/nginx.conf")
    environment = _read(".env.example")
    assert all(
        parsed["services"][name]["read_only"] is True
        for name in ("migrate", "backend", "frontend")
    )
    assert parsed["services"]["backend"]["pids_limit"] == 256
    assert parsed["services"]["frontend"]["pids_limit"] == 128
    assert "/healthz" in " ".join(parsed["services"]["frontend"]["healthcheck"]["test"])
    assert compose.count("cap_drop:") == 2
    assert compose.count("no-new-privileges:true") == 2
    assert 'user: "10001:10001"' in compose
    assert 'user: "101:101"' in compose
    assert "privileged:" not in compose
    assert "/var/run/docker.sock" not in compose
    assert "MCP_SERVER_ENABLED: ${MCP_SERVER_ENABLED:-false}" in compose
    assert "location = /mcp" in nginx
    assert "location ^~ /mcp/" in nginx and "return 404" in nginx
    assert "proxy_request_buffering off" in nginx
    assert "proxy_set_header Authorization $http_authorization" in nginx
    assert "Cross-Origin-Opener-Policy" in nginx
    assert "Cross-Origin-Resource-Policy" in nginx
    assert 'MCP_SERVER_ENABLED=false' in environment
    assert 'MCP_AUTH_MODE=disabled' in environment
    assert 'MCP_REMOTE_CONFIG_PATH=' in environment


def test_frontend_lock_contains_the_security_patch_floors() -> None:
    lock = json.loads(_read("frontend/package-lock.json"))["packages"]
    floors = {
        "node_modules/react-router-dom": "7.18.2",
        "node_modules/react-router": "7.18.2",
        "node_modules/postcss": "8.5.23",
        "node_modules/nanoid": "3.3.18",
        "node_modules/js-yaml": "4.3.1",
        "node_modules/brace-expansion": "1.1.18",
    }
    for package, floor in floors.items():
        assert Version(lock[package]["version"]) >= Version(floor)


def test_retired_fixed_simulation_contract_is_explicitly_archived() -> None:
    legacy = _read("backend/tests/integration/api/test_incidents.py")
    assert "pytestmark = pytest.mark.skip" in legacy
    assert "archived fixed-phishing simulation API contract" in legacy
    summary = _read("docs/delivery/project-summary.md")
    assert "固定钓鱼模拟攻击功能和对应产品入口" in summary


def test_final_documents_keep_unverified_external_boundaries_explicit() -> None:
    report = _read("docs/delivery/test-report.md")
    deployment = _read("docs/delivery/deployment-guide.md")
    combined = report + deployment
    for verified in (
        "MCP_CONFORMANCE_TESTED=True",
        "MIGRATION_ROUNDTRIP_TESTED=True",
        "POWERSHELL_PARSE_TESTED=True",
        "STATIC_CONTAINER_CONTRACT_TESTED=True",
    ):
        assert verified in combined
    for boundary in (
        "DOCKER_RUNTIME_TESTED=False",
        "WINDOWS_COMBINED_VERIFY_TESTED=False",
        "NETWORK_ACCESS_TESTED=False",
        "REAL_MODEL_PLANNING_TESTED=False",
        "REAL_IDENTITY_PLATFORM_TESTED=False",
        "REAL_EXTERNAL_MCP_PEER_TESTED=False",
        "REAL_DEVICE_PATHS_TESTED=False",
    ):
        assert boundary in combined
