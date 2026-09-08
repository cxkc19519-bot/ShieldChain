"""File-based, allowlisted model control. No Docker socket in the API container."""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ModuleNotFoundError:  # Windows development and CI use a process-local fallback.
    fcntl = None  # type: ignore[assignment]

_PROCESS_LOCK = threading.RLock()

MODELS = {
    "qwen3": {
        "id": "qwen3",
        "name": "Qwen3-30B-A3B-Instruct-2507-FP8",
        "served_name": "shieldchain-qwen3-30b",
    },
    "qwen38": {"id": "qwen38", "name": "Qwen3.8-27B-FP8", "served_name": "shieldchain-qwen38-27b"},
}


class ControlError(Exception):
    pass


def root() -> Path:
    value = os.environ.get("QWEN_CONTROL_ROOT")
    if not value:
        raise ControlError("模型切换服务未配置")
    return Path(value)


@contextmanager
def lock(name="control.lock", *, shared=False, blocking=True):
    with (root() / name).open("a") as handle:
        if hasattr(os, "getuid") and os.fstat(handle.fileno()).st_uid == os.getuid():
            os.fchmod(handle.fileno(), 0o660)
        if fcntl is None:
            acquired = _PROCESS_LOCK.acquire(blocking=blocking)
            if not acquired:
                raise ControlError("模型正在切换，请等待加载完成")
            try:
                yield
            finally:
                _PROCESS_LOCK.release()
            return
        try:
            mode = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | (
                0 if blocking else fcntl.LOCK_NB
            )
            fcntl.flock(handle, mode)
        except BlockingIOError:
            raise ControlError("模型正在切换，请等待加载完成") from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read(name: str) -> dict:
    try:
        return json.loads((root() / name).read_text())
    except (FileNotFoundError, ValueError):
        return {}


def write(name: str, value: dict):
    path = root() / (name + "." + uuid.uuid4().hex + ".tmp")
    path.write_text(json.dumps(value, ensure_ascii=False))
    path.chmod(0o660)
    path.replace(root() / name)


def catalog() -> dict:
    with lock():
        state = read("state.json")
        heartbeat = read("heartbeat.json")
        request = read("request.json")
    fresh = time.time() - heartbeat.get("time", 0) < 30
    if not fresh:
        state = {
            **state,
            "phase": "unavailable",
            "ready": False,
            "message": "模型控制服务暂不可用，请联系管理员",
        }
    elif request and request.get("id") != state.get("request_id"):
        state = {
            **state,
            "phase": "queued",
            "target_model": request.get("model"),
            "ready": False,
            "message": "已排队，准备切换模型",
        }
    can_switch = fresh and heartbeat.get("can_switch", True)
    if fresh and not can_switch:
        state = {**state, "message": "原模型可用；自动切换权限尚未启用"}
    return {**state, "can_switch": can_switch, "models": list(MODELS.values())}


def select(model: str) -> dict:
    if model not in MODELS:
        raise ControlError("不支持的模型")
    current = catalog()
    if not current["can_switch"]:
        raise ControlError(current["message"])
    with lock():
        state = read("state.json")
        queued = read("request.json")
        switching = state.get("phase") in {"switching", "loading", "rollback"}
        pending = queued and queued.get("id") != state.get("request_id")
        if switching or pending:
            raise ControlError("已有切换任务，请等待完成后再操作")
        if state.get("ready") and state.get("active_model") == model:
            return current
        write("request.json", {"id": uuid.uuid4().hex, "model": model})
    return catalog()


@contextmanager
def inference(model: str):
    with lock("inference.lock", shared=True, blocking=False):
        state = catalog()
        if not state.get("ready") or state.get("active_model") != model:
            raise ControlError("所选模型尚未就绪，请先启动并等待加载完成")
        yield MODELS[model]["served_name"]
