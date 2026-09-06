"""Authenticated bridge for Wazuh metadata and bounded endpoint containment."""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import socketserver
import ssl
from hmac import compare_digest
from http import HTTPStatus
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

TOKEN = os.environ.get("SHIELDCHAIN_WAZUH_EXECUTOR_TOKEN", "")
SOCKET_PATH = os.environ.get(
    "SHIELDCHAIN_WAZUH_EXECUTOR_SOCKET", "/run/shieldchain-wazuh-executor/executor.sock"
)
ENDPOINT_SOCKET_PATH = os.environ.get(
    "SHIELDCHAIN_ENDPOINT_EXECUTOR_SOCKET",
    "/run/shieldchain-endpoint-executor/executor.sock",
)
API_URL = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000").rstrip("/")
API_USERNAME = os.environ.get("WAZUH_API_USERNAME") or os.environ.get("API_USERNAME", "")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD") or os.environ.get("API_PASSWORD", "")
ALLOWED_AGENT_IDS = frozenset(
    item.strip()
    for item in os.environ.get("SHIELDCHAIN_WAZUH_ALLOWED_AGENT_IDS", "002").split(",")
    if item.strip()
)
_AGENT_ID = re.compile(r"^[0-9]{3,8}$")
_TLS = ssl.create_default_context()
if os.environ.get("WAZUH_API_TLS_VERIFY", "false").casefold() != "true":
    _TLS = ssl._create_unverified_context()


def api_request(path: str, *, authorization: str) -> dict[str, object] | str:
    request = Request(API_URL + path, headers={"Authorization": authorization})
    try:
        with urlopen(request, timeout=4, context=_TLS) as response:
            raw = response.read(65_537)
    except HTTPError as error:
        raise RuntimeError(f"Wazuh API rejected the request ({error.code})") from None
    except (TimeoutError, URLError):
        raise RuntimeError("Wazuh API is unavailable") from None
    if len(raw) > 65_536:
        raise RuntimeError("Wazuh API response is too large")
    text = raw.decode("utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def authenticate() -> str:
    credentials = base64.b64encode(f"{API_USERNAME}:{API_PASSWORD}".encode()).decode("ascii")
    result = api_request(
        "/security/user/authenticate?raw=true",
        authorization=f"Basic {credentials}",
    )
    if not isinstance(result, str) or len(result) < 32:
        raise RuntimeError("Wazuh API authentication failed")
    return result


def query_agent(agent_id: str) -> dict[str, object]:
    token = authenticate()
    query = urlencode(
        {
            "agents_list": agent_id,
            "select": "id,name,status,ip,version,lastKeepAlive",
        }
    )
    result = api_request(f"/agents?{query}", authorization=f"Bearer {token}")
    if not isinstance(result, dict):
        raise RuntimeError("Wazuh API returned an invalid agent response")
    data = result.get("data")
    items = data.get("affected_items") if isinstance(data, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError("allowed Wazuh agent was not found")
    item = items[0]
    status = str(item.get("status", "unknown")).casefold()
    return {
        "ok": True,
        "agent_id": str(item.get("id", agent_id)),
        "agent_name": str(item.get("name", ""))[:128],
        "agent_status": status[:32],
        "agent_ip": str(item.get("ip", ""))[:64],
        "agent_version": str(item.get("version", ""))[:128],
        "last_keepalive": str(item.get("lastKeepAlive", ""))[:64],
        "summary": f"Wazuh agent {agent_id} state query completed.",
    }


class UnixHTTPConnection(HTTPConnection):
    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost", timeout=4)
        self._socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self._socket_path)
        self.sock = connection


def endpoint_request(path: str, payload: dict[str, object]) -> dict[str, object]:
    connection = UnixHTTPConnection(ENDPOINT_SOCKET_PATH)
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload, separators=(",", ":")),
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        raw = response.read(16_385)
        if response.status >= 400:
            raise RuntimeError(f"endpoint executor rejected the request ({response.status})")
    except (OSError, TimeoutError):
        raise RuntimeError("endpoint executor is unavailable") from None
    finally:
        connection.close()
    if len(raw) > 16_384:
        raise RuntimeError("endpoint executor response is too large")
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("endpoint executor returned invalid JSON") from None
    if not isinstance(decoded, dict) or decoded.get("ok") is not True:
        raise RuntimeError("endpoint executor did not confirm the request")
    return decoded


def query_endpoint(agent_id: str) -> dict[str, object]:
    containment = endpoint_request("/v1/endpoint/query", {"agent_id": agent_id})
    try:
        metadata = query_agent(agent_id)
    except RuntimeError:
        containment["agent_status"] = "unavailable"
        containment["summary"] = (
            f"Endpoint {agent_id} containment state queried; Wazuh API is unavailable."
        )
        return containment
    metadata.update(containment)
    metadata["summary"] = f"Wazuh agent {agent_id} and containment state queried."
    return metadata


def isolate_endpoint(agent_id: str, ttl_seconds: int) -> dict[str, object]:
    query_agent(agent_id)
    return endpoint_request(
        "/v1/endpoint/isolate",
        {"agent_id": agent_id, "ttl_seconds": ttl_seconds},
    )


def restore_endpoint(agent_id: str) -> dict[str, object]:
    return endpoint_request("/v1/endpoint/restore", {"agent_id": agent_id})


class Handler(BaseHTTPRequestHandler):
    server_version = "ShieldChainWazuhExecutor/1"

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send(HTTPStatus.NOT_FOUND, {"ok": False})
            return
        self._send(HTTPStatus.OK, {"ok": True, "mode": "wazuh-endpoint-bridge"})

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
            if not isinstance(payload, dict) or "agent_id" not in payload:
                raise ValueError("request body must contain agent_id")
            agent_id = payload.get("agent_id")
            if (
                not isinstance(agent_id, str)
                or not _AGENT_ID.fullmatch(agent_id)
                or agent_id not in ALLOWED_AGENT_IDS
            ):
                raise ValueError("agent_id is outside the configured allowlist")
            if self.path == "/v1/wazuh/agent/query" and set(payload) == {"agent_id"}:
                result = query_endpoint(agent_id)
            elif self.path == "/v1/wazuh/agent/isolate" and set(payload) == {
                "agent_id",
                "ttl_seconds",
            }:
                ttl = payload["ttl_seconds"]
                if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 86_400:
                    raise ValueError("ttl_seconds must be between 60 and 86400")
                result = isolate_endpoint(agent_id, ttl)
            elif self.path == "/v1/wazuh/agent/restore" and set(payload) == {"agent_id"}:
                result = restore_endpoint(agent_id)
            else:
                self._send(HTTPStatus.NOT_FOUND, {"ok": False})
                return
            self._send(HTTPStatus.OK, result)
        except (ValueError, json.JSONDecodeError) as error:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)[:256]})
        except RuntimeError:
            self._send(HTTPStatus.BAD_GATEWAY, {"ok": False, "error": "wazuh_api_failure"})

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
    parsed = urlsplit(API_URL)
    if parsed.scheme != "https" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("WAZUH_API_URL must be local HTTPS")
    if len(TOKEN) < 24:
        raise SystemExit("SHIELDCHAIN_WAZUH_EXECUTOR_TOKEN must contain at least 24 characters")
    if not API_USERNAME or not API_PASSWORD or not ALLOWED_AGENT_IDS:
        raise SystemExit("Wazuh API credentials and agent allowlist are required")
    if any(not _AGENT_ID.fullmatch(item) for item in ALLOWED_AGENT_IDS):
        raise SystemExit("SHIELDCHAIN_WAZUH_ALLOWED_AGENT_IDS contains an invalid id")
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o755, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    server = ThreadingUnixHTTPServer(SOCKET_PATH, Handler)
    os.chmod(SOCKET_PATH, 0o660)
    server.serve_forever()
