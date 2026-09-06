#!/usr/bin/env python3
"""Verify the bounded Wazuh endpoint query/isolate/restore bridge."""

from __future__ import annotations

import argparse
import json
import os
import socket
import time
from http.client import HTTPConnection


class UnixHTTPConnection(HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=5)
        self._path = path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self._path)
        self.sock = connection


def post(path: str, payload: dict[str, object], *, expected_status: int = 200) -> dict:
    socket_path = os.environ.get(
        "RESPONSE_WAZUH_EXECUTOR_URL",
        "http+unix:///run/shieldchain-wazuh-executor/executor.sock",
    ).removeprefix("http+unix://")
    token = os.environ.get("RESPONSE_FIREWALL_EXECUTOR_TOKEN", "")
    if len(token) < 24:
        raise RuntimeError("executor token is unavailable")
    connection = UnixHTTPConnection(socket_path)
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload, separators=(",", ":")),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        body = response.read(16_385)
    finally:
        connection.close()
    if response.status != expected_status:
        raise RuntimeError(f"unexpected executor status: {response.status}")
    decoded = json.loads(body)
    if not isinstance(decoded, dict):
        raise RuntimeError("executor returned a non-object response")
    return decoded


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--verify-ttl", action="store_true")
    arguments = parser.parse_args()
    if not arguments.execute:
        parser.error("--execute is required because this check briefly changes endpoint state")

    agent = {"agent_id": "002"}
    isolated = False
    try:
        before = post("/v1/wazuh/agent/query", agent)
        assert before["isolation_status"] == "connected", before
        assert before["agent_status"] == "active", before
        changed = post(
            "/v1/wazuh/agent/isolate",
            {"agent_id": "002", "ttl_seconds": 60},
        )
        isolated = True
        assert changed["isolation_status"] == "isolated", changed
        during = post("/v1/wazuh/agent/query", agent)
        assert during["isolation_status"] == "isolated", during
        assert during["agent_status"] == "active", during
        restored = post("/v1/wazuh/agent/restore", agent)
        isolated = False
        assert restored["isolation_status"] == "connected", restored
        after = post("/v1/wazuh/agent/query", agent)
        assert after["isolation_status"] == "connected", after
        assert after["agent_status"] == "active", after
        rejected = post("/v1/wazuh/agent/query", {"agent_id": "001"}, expected_status=400)
        assert rejected.get("ok") is False, rejected
        if arguments.verify_ttl:
            post(
                "/v1/wazuh/agent/isolate",
                {"agent_id": "002", "ttl_seconds": 60},
            )
            isolated = True
            time.sleep(65)
            expired = post("/v1/wazuh/agent/query", agent)
            assert expired["isolation_status"] == "connected", expired
            assert expired["agent_status"] == "active", expired
            isolated = False
    finally:
        if isolated:
            post("/v1/wazuh/agent/restore", agent)

    print("endpoint_response_e2e=passed")
    print("agent_id=002")
    print("states=connected,isolated,connected")
    print("wazuh_agent_status=active")
    print("out_of_scope_agent_001=rejected")
    print(f"ttl_auto_restore={'passed' if arguments.verify_ttl else 'not_requested'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
