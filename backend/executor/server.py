"""Minimal authenticated HTTP executor for ShieldChain nftables actions."""

from __future__ import annotations

import ipaddress
import json
import os
import socketserver
import subprocess
from hmac import compare_digest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

TABLE = "shieldchain"
SET = "blocked_ipv4"
TOKEN = os.environ.get("SHIELDCHAIN_FIREWALL_EXECUTOR_TOKEN", "")
SOCKET_PATH = os.environ.get(
    "SHIELDCHAIN_FIREWALL_EXECUTOR_SOCKET", "/run/shieldchain-executor/executor.sock"
)
ALLOWED = tuple(
    ipaddress.ip_network(item.strip())
    for item in os.environ.get(
        "SHIELDCHAIN_FIREWALL_ALLOWED_CIDRS",
        "192.0.2.0/24,198.51.100.0/24,203.0.113.0/24",
    ).split(",")
    if item.strip()
)


def nft(statement: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nft", "-f", "-"],
        input=statement + "\n",
        text=True,
        capture_output=True,
        timeout=3,
        check=check,
    )


def ensure_table() -> None:
    listed = subprocess.run(
        ["nft", "list", "table", "inet", TABLE],
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    if listed.returncode == 0:
        return
    nft(f"add table inet {TABLE}")
    nft(f"add set inet {TABLE} {SET} {{ type ipv4_addr; flags timeout; }}")
    nft(f"add chain inet {TABLE} input {{ type filter hook input priority -5; policy accept; }}")
    nft(f"add rule inet {TABLE} input ip saddr @{SET} counter drop")
    nft(f"add chain inet {TABLE} output {{ type filter hook output priority -5; policy accept; }}")
    nft(f"add rule inet {TABLE} output ip daddr @{SET} counter drop")


def allowed_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("target_ip must be a string")
    address = ipaddress.ip_address(value.strip())
    if not isinstance(address, ipaddress.IPv4Address) or not any(address in net for net in ALLOWED):
        raise ValueError("target_ip is outside the configured response allowlist")
    return str(address)


def is_blocked(target: str) -> bool:
    result = nft(f"get element inet {TABLE} {SET} {{ {target} }}", check=False)
    return result.returncode == 0


class Handler(BaseHTTPRequestHandler):
    server_version = "ShieldChainExecutor/1"

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send(HTTPStatus.NOT_FOUND, {"ok": False})
            return
        self._send(HTTPStatus.OK, {"ok": True, "mode": "nftables"})

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
            if not isinstance(payload, dict):
                raise ValueError("request body must be an object")
            target = allowed_ip(payload.get("target_ip"))
            if self.path == "/v1/firewall/query":
                blocked = is_blocked(target)
                self._send(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "firewall_status": "blocked" if blocked else "not_blocked",
                        "summary": "Firewall state query completed.",
                    },
                )
                return
            if self.path == "/v1/firewall/block":
                ttl = payload.get("ttl_seconds")
                if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 86400:
                    raise ValueError("ttl_seconds must be between 60 and 86400")
                if not is_blocked(target):
                    nft(f"add element inet {TABLE} {SET} {{ {target} timeout {ttl}s }}")
                if not is_blocked(target):
                    raise RuntimeError("firewall verification failed")
                self._send(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "firewall_status": "blocked",
                        "summary": f"IP blocked by nftables for {ttl} seconds.",
                    },
                )
                return
            if self.path == "/v1/firewall/unblock":
                nft(f"delete element inet {TABLE} {SET} {{ {target} }}", check=False)
                self._send(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "firewall_status": "not_blocked",
                        "summary": "IP removed from the ShieldChain nftables set.",
                    },
                )
                return
            self._send(HTTPStatus.NOT_FOUND, {"ok": False})
        except (ValueError, json.JSONDecodeError) as error:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)[:256]})
        except (RuntimeError, subprocess.SubprocessError):
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "executor_failure"},
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
        raise SystemExit("SHIELDCHAIN_FIREWALL_EXECUTOR_TOKEN must contain at least 24 characters")
    if not ALLOWED:
        raise SystemExit("SHIELDCHAIN_FIREWALL_ALLOWED_CIDRS must not be empty")
    ensure_table()
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o755, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    server = ThreadingUnixHTTPServer(SOCKET_PATH, Handler)
    os.chmod(SOCKET_PATH, 0o666)
    server.serve_forever()
