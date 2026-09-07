"""Narrow proxy for the server-owned isolated NTA demo replay runner."""

from __future__ import annotations

import json
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from fastapi import APIRouter, Request as FastApiRequest, status

from shieldchain.core.config import Settings
from shieldchain.core.errors import ApiError


router = APIRouter(prefix="/nta/demo-replay", tags=["nta-demo-replay"])


def _settings(request: FastApiRequest) -> Settings:
    return cast(Settings, request.app.state.settings)


def _runner_request(request: FastApiRequest, method: str, path: str) -> dict[str, object]:
    settings = _settings(request)
    if not settings.nta_demo_replay_enabled or settings.nta_demo_replay_runner_url is None:
        raise ApiError("nta_demo_replay_disabled", "演示回放未在此环境启用", 503)
    token = settings.nta_demo_replay_runner_token.get_secret_value()
    if len(token) < 24:
        raise ApiError("nta_demo_replay_unconfigured", "演示回放服务未完成安全配置", 503)
    url = urljoin(str(settings.nta_demo_replay_runner_url), path.lstrip("/"))
    runner_request = Request(
        url,
        data=b"" if method == "POST" else None,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ShieldChain-Nta-Replay-Token": token,
        },
    )
    try:
        with urlopen(runner_request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError):
        raise ApiError("nta_demo_replay_unavailable", "演示回放服务暂不可用", 503) from None
    if not isinstance(payload, dict):
        raise ApiError("nta_demo_replay_invalid_response", "演示回放服务返回无效状态", 502)
    return cast(dict[str, object], payload)


@router.get("/status")
def status_view(request: FastApiRequest) -> dict[str, object]:
    return _runner_request(request, "GET", "/v1/demo-replay/status")


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
def start_replay(request: FastApiRequest) -> dict[str, object]:
    """Start one server-selected allowlisted sample; HTTP clients choose nothing."""
    return _runner_request(request, "POST", "/v1/demo-replay/start")
