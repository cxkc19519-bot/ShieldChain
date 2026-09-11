from pathlib import Path

import pytest

from shieldchain.mcp_remote.peer_config import load_mcp_remote_config

VALID_CONFIG = """\
version: 1
servers:
  - id: approved-security-platform
    enabled: true
    transport: streamable_http
    endpoint: https://security-platform.example.test/mcp
    auth:
      mode: bearer_env
      token_env: APPROVED_SECURITY_PLATFORM_MCP_TOKEN
    network_policy: public_https
    allowed_tools:
      - remote_name: alerts_list
        alias: external.approved_security_platform.alerts.list
        schema_revision: approved-v1
        classification: read_only
        allowed_roles: [alert_triage, threat_investigation]
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "servers.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_strict_server_owned_configuration(tmp_path: Path) -> None:
    config = load_mcp_remote_config(_write(tmp_path, VALID_CONFIG))

    assert config.version == 1
    assert len(config.servers) == 1
    peer = config.servers[0]
    assert peer.id == "approved-security-platform"
    assert peer.auth.token_env == "APPROVED_SECURITY_PLATFORM_MCP_TOKEN"
    assert peer.allowed_tools[0].classification == "read_only"
    assert peer.allowed_tools[0].schema_revision == "approved-v1"


@pytest.mark.parametrize(
    "text, expected",
    [
        (VALID_CONFIG.replace("version: 1", "version: 2"), "version"),
        (
            VALID_CONFIG.replace("    endpoint:", "    unexpected: true\n    endpoint:"),
            "unexpected",
        ),
        (VALID_CONFIG.replace("mode: bearer_env", "mode: raw_token"), "mode"),
        (VALID_CONFIG.replace("transport: streamable_http", "transport: stdio"), "transport"),
        (
            VALID_CONFIG.replace("classification: read_only", "classification: destructive"),
            "classification",
        ),
        (VALID_CONFIG.replace("https://", "http://"), "HTTPS"),
        (VALID_CONFIG.replace("/mcp", "/mcp?target=http://127.0.0.1"), "query"),
        (
            VALID_CONFIG.replace(
                "    network_policy: public_https",
                "    network_policy: public_https\n    tls_ca_bundle: relative/ca.pem",
            ),
            "absolute path",
        ),
        (VALID_CONFIG.replace("version: 1", "version: 1\nversion: 1"), "duplicate YAML key"),
        (
            VALID_CONFIG.replace(
                "  - id: approved-security-platform",
                "  - id: approved-security-platform",
            )
            + VALID_CONFIG.split("servers:\n", 1)[1],
            "duplicate server id",
        ),
    ],
)
def test_rejects_ambiguous_or_unapproved_configuration(
    tmp_path: Path, text: str, expected: str
) -> None:
    with pytest.raises(ValueError, match=expected):
        load_mcp_remote_config(_write(tmp_path, text))


def test_rejects_duplicate_aliases_and_remote_names(tmp_path: Path) -> None:
    duplicate = VALID_CONFIG.replace(
        "        allowed_roles: [alert_triage, threat_investigation]",
        "        allowed_roles: [alert_triage, threat_investigation]\n"
        "      - remote_name: alerts_list\n"
        "        alias: external.approved_security_platform.alerts.list\n"
        "        schema_revision: approved-v1\n"
        "        classification: read_only\n"
        "        allowed_roles: [alert_triage]",
    )

    with pytest.raises(ValueError, match="duplicate remote tool name"):
        load_mcp_remote_config(_write(tmp_path, duplicate))
