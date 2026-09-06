"""Unix-socket adapter for the least-privilege Wazuh response executor."""

from __future__ import annotations

import json
import socket
from datetime import datetime
from http.client import HTTPConnection
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from shieldchain.tools.domain import (
    ExecutionOutcome,
    PolicyReason,
    ToolVerification,
    VerificationOutcome,
)
from shieldchain.tools.gateway import AdapterExecution, TrustedToolAdapter
from shieldchain.tools.registry import BoundToolRequest
from shieldchain.wazuh.persistence import WazuhCaseRunRow

_WAZUH_TOOLS = frozenset(
    {
        "query_endpoint_state", "isolate_endpoint", "restore_endpoint",
        "query_file_state", "quarantine_file", "restore_file",
    }
)


class WazuhHttpAdapter:
    """Expose only fixed Wazuh operations; arbitrary paths and commands are impossible."""

    def __init__(self, *, base_url: str, token: str, timeout_seconds: float = 4.0) -> None:
        normalized = base_url.rstrip("/")
        if not normalized.startswith("http+unix:///"):
            raise ValueError("Wazuh executor must use an absolute Unix socket URL")
        if len(token) < 24:
            raise ValueError("Wazuh executor token must contain at least 24 characters")
        self._socket_path = normalized.removeprefix("http+unix://")
        self._token = token
        self._timeout = timeout_seconds

    def execute(self, request: BoundToolRequest) -> AdapterExecution:
        if request.registration.definition.name not in _WAZUH_TOOLS:
            return AdapterExecution(
                ExecutionOutcome.FAILED,
                "The real Wazuh connector does not support this tool.",
                "unsupported_real_tool",
            )
        tool = request.registration.definition.name
        path = {
            "query_endpoint_state": "/v1/wazuh/agent/query",
            "isolate_endpoint": "/v1/wazuh/agent/isolate",
            "restore_endpoint": "/v1/wazuh/agent/restore",
            "query_file_state": "/v1/wazuh/file/query",
            "quarantine_file": "/v1/wazuh/file/quarantine",
            "restore_file": "/v1/wazuh/file/restore",
        }[tool]
        payload: dict[str, object] = {
            "agent_id": str(request.request.arguments["endpoint_id"])
        }
        if tool == "isolate_endpoint":
            payload["ttl_seconds"] = int(
                request.request.arguments["isolation_ttl_seconds"]
            )
        if tool in {"query_file_state", "quarantine_file", "restore_file"}:
            payload["file_id"] = str(request.request.arguments["file_id"])
        response = self._post(path, payload)
        return AdapterExecution(
            ExecutionOutcome.SUCCEEDED,
            str(response.get("summary") or "Wazuh agent state query completed."),
        )

    def verify(
        self,
        request: BoundToolRequest,
        execution: AdapterExecution,
        *,
        now: datetime,
    ) -> ToolVerification:
        del execution
        try:
            is_file = request.registration.definition.name in {
                "query_file_state", "quarantine_file", "restore_file"
            }
            path = "/v1/wazuh/file/query" if is_file else "/v1/wazuh/agent/query"
            payload = {"agent_id": str(request.request.arguments["endpoint_id"])}
            if is_file:
                payload["file_id"] = str(request.request.arguments["file_id"])
            response = self._post(path, payload)
            field = "file_status" if is_file else "isolation_status"
            observed = {field: str(response[field])}
            verified = observed == dict(request.request.expected_state)
            outcome = VerificationOutcome.VERIFIED if verified else VerificationOutcome.FAILED
            reason = None if verified else PolicyReason.VERIFICATION_FAILED
        except (KeyError, ValueError, RuntimeError):
            observed = {"verification_status": "unavailable"}
            outcome = VerificationOutcome.INCONCLUSIVE
            reason = PolicyReason.VERIFICATION_FAILED
        return ToolVerification(
            uuid4(),
            request.request.id,
            outcome,
            observed,
            request.request.evidence,
            reason,
            now,
        )

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        connection = _UnixHTTPConnection(self._socket_path, timeout=self._timeout)
        try:
            connection.request(
                "POST",
                path,
                body=json.dumps(payload, separators=(",", ":")),
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            raw = response.read(16_385)
            if response.status >= 400:
                raise RuntimeError(f"Wazuh executor rejected the request ({response.status})")
        except (OSError, TimeoutError):
            raise RuntimeError("Wazuh executor is unavailable") from None
        finally:
            connection.close()
        if len(raw) > 16_384:
            raise RuntimeError("Wazuh executor response is too large")
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("Wazuh executor returned invalid JSON") from None
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise RuntimeError("Wazuh executor did not confirm the request")
        return decoded


class _UnixHTTPConnection(HTTPConnection):
    def __init__(self, socket_path: str, *, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self._socket_path)
        self.sock = connection


class _RoutedAdapter:
    def __init__(self, wazuh: WazuhHttpAdapter, fallback: TrustedToolAdapter) -> None:
        self._wazuh = wazuh
        self._fallback = fallback

    def execute(self, request: BoundToolRequest) -> AdapterExecution:
        return self._select(request).execute(request)

    def verify(
        self,
        request: BoundToolRequest,
        execution: AdapterExecution,
        *,
        now: datetime,
    ) -> ToolVerification:
        return self._select(request).verify(request, execution, now=now)

    def _select(self, request: BoundToolRequest) -> TrustedToolAdapter:
        if request.registration.definition.name in _WAZUH_TOOLS:
            return self._wazuh
        return self._fallback


class WazuhAdapterProvider:
    """Route Wazuh-bound runs to a real read-only agent connector."""

    def __init__(self, fallback, *, base_url: str, token: str) -> None:
        self._fallback = fallback
        self._wazuh = WazuhHttpAdapter(base_url=base_url, token=token)

    def for_run(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        now: datetime,
    ) -> TrustedToolAdapter | None:
        fallback = self._fallback.for_run(
            session,
            tenant_id=tenant_id,
            run_id=run_id,
            now=now,
        )
        wazuh_run = session.execute(
            select(WazuhCaseRunRow.run_id).where(
                WazuhCaseRunRow.run_id == str(run_id),
                WazuhCaseRunRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        if wazuh_run is None:
            return fallback
        return self._wazuh if fallback is None else _RoutedAdapter(self._wazuh, fallback)
