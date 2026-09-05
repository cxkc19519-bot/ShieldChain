"""HTTP adapter for the least-privilege nftables response executor."""

from __future__ import annotations

import json
import socket
from datetime import datetime
from http.client import HTTPConnection
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
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

_FIREWALL_TOOLS = frozenset({"query_firewall_state", "block_ip"})


class AdapterProvider(Protocol):
    def for_run(
        self,
        session: Session,
        *,
        tenant_id: UUID,
        run_id: UUID,
        now: datetime,
    ) -> TrustedToolAdapter | None: ...


class NftablesHttpAdapter:
    """Call a narrow executor API; arbitrary commands are never accepted."""

    def __init__(self, *, base_url: str, token: str, timeout_seconds: float = 4.0) -> None:
        normalized = base_url.rstrip("/")
        self._unix_socket = None
        if normalized.startswith("http+unix:///"):
            self._unix_socket = normalized.removeprefix("http+unix://")
        elif not normalized.startswith(("http://", "https://")):
            raise ValueError("firewall executor URL must be HTTP, HTTPS, or http+unix")
        if len(token) < 24:
            raise ValueError("firewall executor token must contain at least 24 characters")
        self._base_url = normalized
        self._token = token
        self._timeout = timeout_seconds

    def execute(self, request: BoundToolRequest) -> AdapterExecution:
        name = request.registration.definition.name
        if name not in _FIREWALL_TOOLS:
            return AdapterExecution(
                ExecutionOutcome.FAILED,
                "The real firewall connector does not support this tool.",
                "unsupported_real_tool",
            )
        payload: dict[str, object] = {"target_ip": str(request.request.arguments["target_ip"])}
        path = "/v1/firewall/query"
        if name == "block_ip":
            path = "/v1/firewall/block"
            payload["ttl_seconds"] = int(request.request.arguments["rule_ttl_seconds"])
        response = self._post(path, payload)
        return AdapterExecution(
            ExecutionOutcome.SUCCEEDED,
            str(response.get("summary") or "Firewall connector request completed."),
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
            response = self._post(
                "/v1/firewall/query",
                {"target_ip": str(request.request.arguments["target_ip"])},
            )
            observed = {"firewall_status": str(response["firewall_status"])}
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
        if self._unix_socket is not None:
            return self._post_unix(path, payload)
        request = Request(
            self._base_url + path,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                raw = response.read(16_385)
        except HTTPError as error:
            raise RuntimeError(f"firewall executor rejected the request ({error.code})") from None
        except (TimeoutError, URLError):
            raise RuntimeError("firewall executor is unavailable") from None
        if len(raw) > 16_384:
            raise RuntimeError("firewall executor response is too large")
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("firewall executor returned invalid JSON") from None
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise RuntimeError("firewall executor did not confirm the request")
        return decoded

    def _post_unix(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        connection = _UnixHTTPConnection(self._unix_socket, timeout=self._timeout)
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
                raise RuntimeError(f"firewall executor rejected the request ({response.status})")
        except (OSError, TimeoutError):
            raise RuntimeError("firewall executor is unavailable") from None
        finally:
            connection.close()
        if len(raw) > 16_384:
            raise RuntimeError("firewall executor response is too large")
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("firewall executor returned invalid JSON") from None
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise RuntimeError("firewall executor did not confirm the request")
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


class RoutedAdapter:
    """Route only firewall tools to the real connector."""

    def __init__(self, firewall: NftablesHttpAdapter, fallback: TrustedToolAdapter) -> None:
        self._firewall = firewall
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
        if request.registration.definition.name in _FIREWALL_TOOLS:
            return self._firewall
        return self._fallback


class NftablesAdapterProvider:
    """Add a durable firewall connector to the existing per-run provider."""

    def __init__(self, fallback: AdapterProvider, *, base_url: str, token: str) -> None:
        self._fallback = fallback
        self._firewall = NftablesHttpAdapter(base_url=base_url, token=token)

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
        if fallback is not None:
            return RoutedAdapter(self._firewall, fallback)
        wazuh_run = session.execute(
            select(WazuhCaseRunRow.run_id).where(
                WazuhCaseRunRow.run_id == str(run_id),
                WazuhCaseRunRow.tenant_id == str(tenant_id),
            )
        ).scalar_one_or_none()
        return self._firewall if wazuh_run is not None else None
