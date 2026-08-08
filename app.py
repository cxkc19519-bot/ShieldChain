"""One-command local launcher for ShieldChain on Windows."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONDA_PREFIX = Path(r"D:\anaconda\envs\ShieldChain")
CONDA_PYTHON = CONDA_PREFIX / "python.exe"
BACKEND_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://127.0.0.1:5173"
MILVUS_PORT = 19530
LOCAL_RAG_PORT = 8001
MILVUS_COMPOSE = ROOT / "docker-compose.rag-local.yml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start the ShieldChain backend and frontend."
    )
    parser.add_argument(
        "--check", action="store_true", help="Check prerequisites only."
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Do not open the frontend."
    )
    parser.add_argument(
        "--skip-migrations",
        action="store_true",
        help="Skip the Alembic upgrade step.",
    )
    return parser.parse_args()


def ensure_conda_python() -> None:
    """Re-execute with the requested Conda interpreter when necessary."""
    if not CONDA_PYTHON.is_file():
        raise SystemExit(f"Conda Python not found: {CONDA_PYTHON}")
    if Path(sys.prefix).resolve() == CONDA_PREFIX.resolve():
        return
    print(f"Switching to Conda environment: {CONDA_PREFIX}")
    os.execv(
        str(CONDA_PYTHON),
        [str(CONDA_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]],
    )


def port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def prepare_environment() -> tuple[Path, Path]:
    env_file = ROOT / ".env"
    env_example = ROOT / ".env.example"
    if not env_file.exists():
        if not env_example.is_file():
            raise SystemExit("Missing both .env and .env.example.")
        shutil.copyfile(env_example, env_file)
        print("Created local .env from .env.example.")

    node = shutil.which("node.exe") or shutil.which("node")
    vite = ROOT / "frontend" / "node_modules" / "vite" / "bin" / "vite.js"
    if node is None:
        raise SystemExit(
            "Node.js is unavailable. Install the current Node.js LTS release."
        )
    if not vite.is_file():
        raise SystemExit(
            "Frontend dependencies are missing. Run: npm.cmd ci --prefix frontend"
        )

    for port in (8000, 5173, LOCAL_RAG_PORT):
        if not port_is_available(port):
            raise SystemExit(
                f"Port {port} is already occupied. Stop its process and retry."
            )
    return Path(node), vite


def ensure_milvus() -> None:
    """Start the local Milvus stack before accepting knowledge uploads."""
    if not port_is_available(MILVUS_PORT):
        print(f"Milvus: 127.0.0.1:{MILVUS_PORT} is already listening.")
        return
    docker = shutil.which("docker.exe") or shutil.which("docker")
    if docker is None:
        raise SystemExit(
            "Docker Desktop is required for the local Milvus vector database."
        )
    try:
        subprocess.run(
            [docker, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            "Docker Desktop is not running. Start Docker Desktop, then run app.py again."
        ) from error
    print("Starting local Milvus vector database...")
    subprocess.run(
        [docker, "compose", "-f", str(MILVUS_COMPOSE), "up", "-d"], cwd=ROOT, check=True
    )
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if not port_is_available(MILVUS_PORT):
            print(f"Milvus: ready on 127.0.0.1:{MILVUS_PORT}.")
            return
        time.sleep(1)
    raise TimeoutError("Milvus did not become ready within 120 seconds.")


def run_migrations() -> None:
    print("Applying database migrations...")
    subprocess.run(
        [
            str(CONDA_PYTHON),
            "-m",
            "alembic",
            "-c",
            str(ROOT / "backend" / "alembic.ini"),
            "upgrade",
            "head",
        ],
        cwd=ROOT,
        check=True,
    )


def start_process(
    command: list[str], working_directory: Path
) -> subprocess.Popen[bytes]:
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    return subprocess.Popen(
        command, cwd=working_directory, creationflags=creation_flags
    )


def wait_until_ready(processes: list[subprocess.Popen[bytes]]) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(
                    f"A service exited early with code {process.returncode}."
                )
        backend_ready = False
        try:
            with urllib.request.urlopen(
                f"{BACKEND_URL}/api/v1/health/live", timeout=1
            ) as response:
                backend_ready = response.status == 200
        except (OSError, urllib.error.URLError):
            pass
        model_ready = not port_is_available(LOCAL_RAG_PORT)
        frontend_ready = not port_is_available(5173)
        if model_ready and backend_ready and frontend_ready:
            return
        time.sleep(0.25)
    raise TimeoutError("Services did not become ready within 120 seconds.")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.terminate()
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    args = parse_args()
    ensure_conda_python()
    node, vite = prepare_environment()
    print(f"Conda environment: {sys.prefix}")
    print(f"Python: {sys.version.split()[0]}")
    if args.check:
        print("ShieldChain startup prerequisites are ready.")
        return 0
    ensure_milvus()
    os.environ.setdefault("SHIELDCHAIN_RAG_MODELS_ROOT", str(ROOT / "data" / "models"))
    if not args.skip_migrations:
        run_migrations()

    model_service: subprocess.Popen[bytes] | None = None
    backend: subprocess.Popen[bytes] | None = None
    frontend: subprocess.Popen[bytes] | None = None
    try:
        model_service = start_process(
            [
                str(CONDA_PYTHON),
                "-m",
                "uvicorn",
                "shieldchain.rag.local_model_server:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(LOCAL_RAG_PORT),
            ],
            ROOT / "backend",
        )
        backend = start_process(
            [
                str(CONDA_PYTHON),
                "-m",
                "uvicorn",
                "shieldchain.main:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
            ],
            ROOT,
        )
        frontend = start_process(
            [str(node), str(vite), "--host", "127.0.0.1", "--port", "5173"],
            ROOT / "frontend",
        )
        wait_until_ready([model_service, backend, frontend])
        print(f"Backend:  {BACKEND_URL}")
        print(f"Frontend: {FRONTEND_URL}")
        print("Press Ctrl+C to stop both services.")
        if not args.no_browser:
            webbrowser.open(FRONTEND_URL)
        while (
            model_service.poll() is None
            and backend.poll() is None
            and frontend.poll() is None
        ):
            time.sleep(0.25)
        failed = (
            model_service
            if model_service.poll() is not None
            else (backend if backend.poll() is not None else frontend)
        )
        raise RuntimeError(
            f"A service exited unexpectedly with code {failed.returncode}."
        )
    except KeyboardInterrupt:
        print("\nStopping ShieldChain...")
        return 0
    finally:
        for process in (frontend, backend, model_service):
            if process is not None:
                stop_process(process)


if __name__ == "__main__":
    raise SystemExit(main())
