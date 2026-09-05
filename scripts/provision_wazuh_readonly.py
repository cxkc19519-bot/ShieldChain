"""Provision a Wazuh API identity limited to reading one agent.

Run this inside the Wazuh manager container. The administrator credentials are
read from its existing API_USERNAME/API_PASSWORD environment variables. The
generated connector credential is written to a caller-selected mode-0600 file
and is never printed.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import ssl
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API_URL = "https://127.0.0.1:55000"
USERNAME = "shieldchain-agent-reader"
AGENT_ID = os.environ.get("SHIELDCHAIN_AGENT_ID", "002")
OUTPUT = Path(os.environ.get("SHIELDCHAIN_CREDENTIAL_OUTPUT", "/tmp/wazuh-readonly.env"))
TLS = ssl._create_unverified_context()


def request(
    path: str,
    *,
    authorization: str,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> dict[str, object] | str:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Authorization": authorization}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        with urlopen(
            Request(API_URL + path, data=body, headers=headers, method=method),
            timeout=8,
            context=TLS,
        ) as response:
            text = response.read(131_073).decode("utf-8")
    except HTTPError as error:
        detail = error.read(513).decode("utf-8", errors="replace")[:512]
        raise RuntimeError(f"Wazuh API returned HTTP {error.code}: {detail}") from None
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(result, dict) or result.get("error") != 0:
        raise RuntimeError("Wazuh API operation failed")
    return result


def login(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    result = request(
        "/security/user/authenticate?raw=true",
        authorization=f"Basic {encoded}",
        method="POST",
    )
    if not isinstance(result, str) or len(result) < 32:
        raise RuntimeError("Wazuh API authentication failed")
    return result


def created_id(result: dict[str, object]) -> int:
    data = result.get("data")
    items = data.get("affected_items") if isinstance(data, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise RuntimeError("Wazuh API did not return one created object")
    value = items[0].get("id")
    if not isinstance(value, int):
        raise TypeError("Wazuh API returned an invalid object id")
    return value


def existing_items(token: str, path: str) -> list[dict[str, object]]:
    result = request(path, authorization=f"Bearer {token}")
    if not isinstance(result, dict):
        raise TypeError("Wazuh API returned an invalid collection")
    data = result.get("data")
    items = data.get("affected_items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise TypeError("Wazuh API returned an invalid collection")
    return [item for item in items if isinstance(item, dict)]


def main() -> None:
    admin_user = os.environ.get("API_USERNAME", "")
    admin_password = os.environ.get("API_PASSWORD", "")
    if not admin_user or not admin_password:
        raise SystemExit("manager API credentials are unavailable")
    if not re.fullmatch(r"[0-9]{3,8}", AGENT_ID):
        raise SystemExit("SHIELDCHAIN_AGENT_ID is invalid")
    admin_token = login(admin_user, admin_password)
    password = secrets.token_urlsafe(36)
    users = existing_items(admin_token, "/security/users")
    matching_users = [item for item in users if item.get("username") == USERNAME]
    if len(matching_users) > 1:
        raise SystemExit("multiple ShieldChain Wazuh API users were found")
    if matching_users:
        user_id = int(matching_users[0]["id"])
        request(
            f"/security/users/{user_id}",
            authorization=f"Bearer {admin_token}",
            method="PUT",
            payload={"password": password},
        )
        admin_token = login(admin_user, admin_password)
    else:
        user_id = created_id(
            request(
                "/security/users",
                authorization=f"Bearer {admin_token}",
                method="POST",
                payload={"username": USERNAME, "password": password},
            )
        )
        admin_token = login(admin_user, admin_password)

    roles = existing_items(admin_token, "/security/roles")
    readonly_roles = [item for item in roles if item.get("name") == "agents_readonly"]
    if len(readonly_roles) != 1:
        raise SystemExit("built-in agents_readonly role was not found")
    role_id = int(readonly_roles[0]["id"])
    assigned_roles = matching_users[0].get("roles", []) if matching_users else []
    if role_id not in assigned_roles:
        request(
            f"/security/users/{user_id}/roles?{urlencode({'role_ids': role_id})}",
            authorization=f"Bearer {admin_token}",
            method="POST",
        )

    reader_token = login(USERNAME, password)
    result = request(
        f"/agents?{urlencode({'agents_list': AGENT_ID, 'select': 'id,name,status'})}",
        authorization=f"Bearer {reader_token}",
    )
    if not isinstance(result, dict):
        raise TypeError("least-privilege Wazuh verification failed")
    OUTPUT.write_text(
        f"WAZUH_API_USERNAME={USERNAME}\nWAZUH_API_PASSWORD={password}\n",
        encoding="utf-8",
    )
    OUTPUT.chmod(0o600)
    print(f"provisioned read-only Wazuh identity for agent {AGENT_ID}")


if __name__ == "__main__":
    main()
