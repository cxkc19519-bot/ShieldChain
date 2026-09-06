"""Authenticated endpoint containment controller for one allowlisted demo agent."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import socketserver
import subprocess
from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from threading import RLock

TOKEN = os.environ.get("SHIELDCHAIN_ENDPOINT_EXECUTOR_TOKEN", "")
SOCKET_PATH = os.environ.get(
    "SHIELDCHAIN_ENDPOINT_EXECUTOR_SOCKET",
    "/run/shieldchain-endpoint-executor/executor.sock",
)
AGENT_ID = os.environ.get("SHIELDCHAIN_ENDPOINT_AGENT_ID", "002")
TABLE = "shieldchain_endpoint"
SET = "isolated_ipv4"
LOCK = RLock()
FILE_ROOT = os.environ.get("SHIELDCHAIN_FILE_LAB_ROOT", "/var/lib/shieldchain-file-lab")
ALLOWED_FILE_IDS = frozenset(
    item.strip()
    for item in os.environ.get(
        "SHIELDCHAIN_ALLOWED_FILE_IDS", "demo-suspicious-marker"
    ).split(",")
    if item.strip()
)
FILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _run(arguments: list[str], *, input_text: str | None = None, check: bool = True) -> str:
    result = subprocess.run(
        ["nft", *arguments],
        input=input_text,
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError("endpoint firewall operation failed")
    return result.stdout


def _endpoint_ipv4() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    finally:
        probe.close()
    if not address or address.startswith("127."):
        raise RuntimeError("endpoint IPv4 address is unavailable")
    return address


def ensure_policy() -> None:
    tables = _run(["list", "tables"], check=False)
    if f"table inet {TABLE}" in tables:
        return
    _run(
        ["-f", "-"],
        input_text=(
            f"add table inet {TABLE}\n"
            f"add set inet {TABLE} {SET} {{ type ipv4_addr; flags timeout; }}\n"
            f"add chain inet {TABLE} output "
            "{ type filter hook output priority -10; policy accept; }\n"
            f'add rule inet {TABLE} output oifname "lo" accept\n'
            f"add rule inet {TABLE} output ct state established,related accept\n"
            f"add rule inet {TABLE} output tcp dport {{ 1514, 1515 }} accept\n"
            f"add rule inet {TABLE} output ip saddr @{SET} reject\n"
        ),
    )


def query() -> dict[str, object]:
    with LOCK:
        ensure_policy()
        address = _endpoint_ipv4()
        result = _run(
            ["get", "element", "inet", TABLE, SET, "{", address, "}"],
            check=False,
        )
    isolated = address in result
    return {
        "ok": True,
        "agent_id": AGENT_ID,
        "endpoint_ip": address,
        "isolation_status": "isolated" if isolated else "connected",
        "summary": f"Endpoint {AGENT_ID} containment state queried.",
    }


def isolate(ttl_seconds: int) -> dict[str, object]:
    with LOCK:
        ensure_policy()
        address = _endpoint_ipv4()
        _run(["delete", "element", "inet", TABLE, SET, "{", address, "}"], check=False)
        _run(
            [
                "add",
                "element",
                "inet",
                TABLE,
                SET,
                "{",
                address,
                "timeout",
                f"{ttl_seconds}s",
                "}",
            ]
        )
        result = query()
    result["ttl_seconds"] = ttl_seconds
    result["summary"] = f"Endpoint {AGENT_ID} isolated with an automatic TTL."
    return result


def restore() -> dict[str, object]:
    with LOCK:
        ensure_policy()
        address = _endpoint_ipv4()
        _run(["delete", "element", "inet", TABLE, SET, "{", address, "}"], check=False)
        result = query()
    result["summary"] = f"Endpoint {AGENT_ID} containment removed."
    return result


def _file_paths(file_id: str) -> tuple[str, str]:
    if file_id not in ALLOWED_FILE_IDS or not FILE_ID.fullmatch(file_id):
        raise ValueError("file_id is outside the configured allowlist")
    return (
        os.path.join(FILE_ROOT, f"{file_id}.active"),
        os.path.join(FILE_ROOT, f"{file_id}.quarantined"),
    )


def _regular_file(path: str) -> bool:
    return os.path.isfile(path) and not os.path.islink(path)


def query_file(file_id: str) -> dict[str, object]:
    active, quarantined = _file_paths(file_id)
    with LOCK:
        active_exists = _regular_file(active)
        quarantined_exists = _regular_file(quarantined)
        if active_exists == quarantined_exists:
            raise ValueError("file state is missing or ambiguous")
        path = quarantined if quarantined_exists else active
        size = os.path.getsize(path)
        if size > 10 * 1024 * 1024:
            raise ValueError("file exceeds the 10 MiB laboratory limit")
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(64 * 1024), b""):
                digest.update(chunk)
    return {
        "ok": True,
        "agent_id": AGENT_ID,
        "file_id": file_id,
        "file_status": "quarantined" if quarantined_exists else "present",
        "sha256": digest.hexdigest(),
        "size_bytes": size,
        "summary": f"Allowlisted file {file_id} state queried.",
    }


def quarantine_file(file_id: str) -> dict[str, object]:
    active, quarantined = _file_paths(file_id)
    with LOCK:
        if _regular_file(quarantined) and not os.path.exists(active):
            return query_file(file_id)
        if not _regular_file(active) or os.path.lexists(quarantined):
            raise ValueError("file is not in a quarantinable state")
        os.replace(active, quarantined)
        # The executor has every Linux capability dropped, including DAC_OVERRIDE.
        # Keep owner-read permission so it can hash the quarantined artifact while
        # removing write and execute access for all principals.
        os.chmod(quarantined, 0o400)
        result = query_file(file_id)
    result["summary"] = f"Allowlisted file {file_id} quarantined atomically."
    return result


def restore_file(file_id: str) -> dict[str, object]:
    active, quarantined = _file_paths(file_id)
    with LOCK:
        if _regular_file(active) and not os.path.exists(quarantined):
            return query_file(file_id)
        if not _regular_file(quarantined) or os.path.lexists(active):
            raise ValueError("file is not in a restorable state")
        os.chmod(quarantined, 0o600)
        os.replace(quarantined, active)
        result = query_file(file_id)
    result["summary"] = f"Allowlisted file {file_id} restored atomically."
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "ShieldChainEndpointExecutor/1"

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send(HTTPStatus.NOT_FOUND, {"ok": False})
            return
        self._send(HTTPStatus.OK, {"ok": True, "mode": "demo-endpoint-containment"})

    def do_POST(self) -> None:
        supplied = self.headers.get("Authorization", "")
        if not TOKEN or not compare_digest(supplied, f"Bearer {TOKEN}"):
            self._send(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 2048:
                raise ValueError("request size is invalid")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or payload.get("agent_id") != AGENT_ID:
                raise ValueError("agent_id is outside the configured allowlist")
            if self.path == "/v1/endpoint/query" and set(payload) == {"agent_id"}:
                result = query()
            elif self.path == "/v1/endpoint/isolate" and set(payload) == {
                "agent_id",
                "ttl_seconds",
            }:
                ttl = payload["ttl_seconds"]
                if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 86_400:
                    raise ValueError("ttl_seconds must be between 60 and 86400")
                result = isolate(ttl)
            elif self.path == "/v1/endpoint/restore" and set(payload) == {"agent_id"}:
                result = restore()
            elif self.path == "/v1/endpoint/file/query" and set(payload) == {
                "agent_id", "file_id"
            }:
                result = query_file(str(payload["file_id"]))
            elif self.path == "/v1/endpoint/file/quarantine" and set(payload) == {
                "agent_id", "file_id"
            }:
                result = quarantine_file(str(payload["file_id"]))
            elif self.path == "/v1/endpoint/file/restore" and set(payload) == {
                "agent_id", "file_id"
            }:
                result = restore_file(str(payload["file_id"]))
            else:
                self._send(HTTPStatus.NOT_FOUND, {"ok": False})
                return
            self._send(HTTPStatus.OK, result)
        except (ValueError, json.JSONDecodeError) as error:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)[:256]})
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            self._send(
                HTTPStatus.BAD_GATEWAY,
                {"ok": False, "error": "endpoint_firewall_failure"},
            )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if __name__ == "__main__":
    if len(TOKEN) < 24:
        raise SystemExit("SHIELDCHAIN_ENDPOINT_EXECUTOR_TOKEN must contain at least 24 characters")
    if AGENT_ID != "002":
        raise SystemExit("only the isolated demo agent 002 is supported")
    if not ALLOWED_FILE_IDS or any(not FILE_ID.fullmatch(item) for item in ALLOWED_FILE_IDS):
        raise SystemExit("SHIELDCHAIN_ALLOWED_FILE_IDS contains an invalid id")
    os.makedirs(FILE_ROOT, mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o755, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    ensure_policy()
    server = ThreadingUnixHTTPServer(SOCKET_PATH, Handler)
    os.chmod(SOCKET_PATH, 0o666)
    server.serve_forever()
