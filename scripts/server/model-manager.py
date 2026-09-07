#!/usr/bin/env python3
"""Run as jhk. Fixed commands and paths only; request files contain model IDs."""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

DEPLOY = Path("/home/user/jhk/project/ShieldChain")
os.environ["QWEN_CONTROL_ROOT"] = str(DEPLOY / "data/model-control")
sys.path.insert(0, str(DEPLOY / "backend/src"))
from shieldchain.qwen_experience.model_control import MODELS, lock, read, write, root

FILES = ["compose.yaml", "compose.server.yaml", "compose.local-llm.yaml"]


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=90, **kwargs)


def detected():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8001/v1/models", timeout=3) as response:
            ids = {x["id"] for x in json.load(response)["data"]}
        for model in ("qwen38", "qwen3"):
            if MODELS[model]["served_name"] in ids:
                return model
    except Exception:
        pass
    return None


def publish(**values):
    with lock():
        state = read("state.json")
        write("state.json", {**state, **values, "updated_at": time.time()})


def heartbeat():
    while True:
        with lock():
            write("heartbeat.json", {"time": time.time(), "can_switch": os.access("/var/run/docker.sock", os.R_OK | os.W_OK)})
        time.sleep(5)


def start(model):
    image = "vllm/vllm-openai:v0.17.0" if model == "qwen38" else "vllm/vllm-openai:v0.13.0"
    run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL)
    cache = Path("/home/user/jhk/huggingface") / ("models--Qwen--" + MODELS[model]["name"])
    revision = (cache / "refs/main").read_text().strip()
    snapshot = cache / "snapshots" / revision
    index = json.loads((snapshot / "model.safetensors.index.json").read_text())
    required = {"config.json", "tokenizer_config.json", *index["weight_map"].values()}
    # Old interrupted downloads may coexist with a complete active snapshot.
    # Check referenced weights, not unrelated .incomplete cache leftovers.
    if any(not (snapshot / name).is_file() or (snapshot / name).stat().st_size == 0 for name in required):
        raise RuntimeError("模型当前快照引用的权重不完整")
    files = FILES + (["compose.qwen38.yaml"] if model == "qwen38" else [])
    args = ["docker", "compose", "--project-directory", str(DEPLOY)]
    for path in files:
        args.extend(["-f", str(DEPLOY / path)])
    args.extend(["up", "-d", "--no-deps", "--pull", "never", "--force-recreate", "local-llm"])
    run(args)
    for _ in range(180):
        if detected() == model:
            publish(message="权重加载完成，正在验证推理响应")
            request = urllib.request.Request(
                "http://127.0.0.1:8001/v1/chat/completions",
                data=json.dumps({"model": MODELS[model]["served_name"],
                    "messages": [{"role": "user", "content": "Write the numbers 1 to 5 separated by commas."}],
                    "max_tokens": 16, "temperature": 0}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=180) as response:
                result = json.load(response)
            if not result.get("choices") or result.get("usage", {}).get("completion_tokens", 0) < 1:
                raise RuntimeError("模型推理自检失败")
            return
        state = run(["docker", "inspect", "shieldchain-local-llm-1", "--format", "{{json .State}}"], capture_output=True, text=True)
        details = json.loads(state.stdout)
        if details.get("Status") in {"exited", "dead", "restarting"} or details.get("Health", {}).get("Status") == "unhealthy":
            raise RuntimeError("模型启动失败，请查看模型服务日志")
        time.sleep(5)
    raise TimeoutError("模型加载超过15分钟")


def main():
    with lock("manager.lock", blocking=False):
        active = detected()
        queued = read("request.json")
        publish(active_model=active, ready=bool(active), phase="ready" if active else "stopped", target_model=None,
                request_id=queued.get("id"), message="模型已就绪" if active else "请选择模型并启动")
        threading.Thread(target=heartbeat, daemon=True).start()
        while True:
            with lock():
                request = read("request.json")
                state = read("state.json")
            if request and request.get("id") != state.get("request_id"):
                target = request.get("model")
                if target not in MODELS:
                    publish(request_id=request.get("id"), phase="error", message="拒绝无效模型请求")
                    continue
                previous = detected()
                publish(request_id=request["id"], phase="switching", target_model=target, ready=False,
                        message="等待当前对话完成后切换；模型加载可能需要数分钟")
                try:
                    with lock("inference.lock"):
                        publish(phase="loading", message="正在加载所选模型，请稍候；其他模型功能暂不可用")
                        start(target)
                        publish(active_model=target, phase="ready", ready=True, target_model=None, message="模型已就绪")
                except Exception as error:
                    print(type(error).__name__, str(error), flush=True)
                    if previous:
                        publish(phase="rollback", message="新模型启动失败，正在恢复原模型")
                        try:
                            with lock("inference.lock"):
                                start(previous)
                        except Exception as rollback_error:
                            print("Rollback failed:", rollback_error, flush=True)
                    active = detected()
                    publish(active_model=active, phase="error", ready=bool(active), target_model=None,
                            message="切换失败；已恢复原模型" if active else "切换失败，模型未就绪；请联系管理员")
            else:
                active = detected()
                publish(active_model=active, ready=bool(active), **({} if state.get("phase") == "error" else
                        {"phase": "ready" if active else "stopped", "message": "模型已就绪" if active else "模型未就绪"}))
            time.sleep(3)


if __name__ == "__main__":
    main()
