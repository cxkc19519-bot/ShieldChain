"""Host-only, token-authenticated runner for allowlisted NTA demo PCAP replay."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DemoSample:
    sample_id: str
    path: Path
    title: str
    sha256: str
    expected_rule_ids: tuple[str, ...]


class DemoReplayRunner:
    def __init__(self, *, manifest: Path, pcap_root: Path, runtime_root: Path) -> None:
        self._manifest = manifest.resolve(strict=True)
        self._pcap_root = pcap_root.resolve(strict=True)
        self._runtime_root = runtime_root.resolve()
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {"state": "idle", "sample": None, "run_id": None}

    def _samples(self) -> list[DemoSample]:
        raw = json.loads(self._manifest.read_text(encoding="utf-8"))
        rows = raw.get("samples") if isinstance(raw, dict) else None
        if not isinstance(rows, list) or not rows:
            raise ValueError("demo replay manifest must contain samples")
        samples: list[DemoSample] = []
        for row in rows:
            if not isinstance(row, dict):
                raise TypeError("demo replay sample is invalid")
            sample_id, relative, title, digest, rule_ids = (
                row.get("id"),
                row.get("path"),
                row.get("title"),
                row.get("sha256"),
                row.get("expected_rule_ids"),
            )
            if not all(isinstance(item, str) and item for item in (sample_id, relative, title, digest)):
                raise ValueError("demo replay sample requires id, path, title and sha256")
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest.casefold()):
                raise ValueError("demo replay sample sha256 is invalid")
            if not isinstance(rule_ids, list) or not all(isinstance(item, str) for item in rule_ids):
                raise ValueError("demo replay sample requires expected_rule_ids")
            path = (self._pcap_root / relative).resolve(strict=True)
            if not path.is_relative_to(self._pcap_root) or path.suffix.casefold() != ".pcap":
                raise ValueError("demo replay sample is outside the allowed PCAP root")
            with path.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if not hmac.compare_digest(actual, digest.casefold()):
                raise ValueError("demo replay sample SHA-256 does not match manifest")
            samples.append(DemoSample(sample_id, path, title, digest.casefold(), tuple(rule_ids)))
        return samples

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._status["state"] == "running":
                return dict(self._status)
            try:
                sample = secrets.choice(self._samples())
            except (OSError, TypeError, ValueError):
                self._status = {"state": "failed", "sample": None, "run_id": None, "reason": "manifest_invalid"}
                return dict(self._status)
            run_id = secrets.token_hex(6)
            self._status = {
                "state": "running",
                "sample": {"id": sample.sample_id, "title": sample.title},
                "run_id": run_id,
            }
        threading.Thread(target=self._run, args=(sample, run_id), daemon=True).start()
        return self.status()

    def _run(self, sample: DemoSample, run_id: str) -> None:
        repository = Path(__file__).resolve().parents[3]
        script = repository / "scripts" / "nta" / "pcap_replay_lab.py"
        output_root = self._runtime_root / "runs"
        command = [
            os.environ.get("PYTHON", "python3"), str(script), str(sample.path),
            "--pcap-root", str(self._pcap_root), "--output-root", str(output_root),
            "--pps", "500", "--timeout", "90", "--acknowledgement",
            "I_UNDERSTAND_ISOLATED_REPLAY",
        ]
        environment = dict(os.environ, SHIELDCHAIN_NTA_REPLAY_ENABLED="true")
        try:
            completed = subprocess.run(
                command, text=True, capture_output=True, timeout=120, env=environment, check=False
            )
            if completed.returncode:
                raise RuntimeError("isolated replay failed")
            output_dir = Path(completed.stdout.strip()).resolve(strict=True)
            events = output_dir / "events.jsonl"
            event_rows = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines() if line]
            rule_ids = {str(item.get("rule_id")) for item in event_rows if isinstance(item, dict)}
            if not rule_ids.intersection(sample.expected_rule_ids):
                raise RuntimeError("replay completed but expected detection was not observed")
            ingest = repository / "scripts" / "nta" / "ingest_nta_events.py"
            ingested = subprocess.run(
                [command[0], str(ingest), str(events)],
                text=True,
                capture_output=True,
                timeout=60,
                env=environment,
                check=False,
            )
            if ingested.returncode:
                raise RuntimeError("replay detection could not be imported")
            result: dict[str, Any] = {"state": "completed", "sample": {"id": sample.sample_id, "title": sample.title}, "run_id": run_id, "alert_count": len(event_rows)}
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result = {"state": "failed", "sample": {"id": sample.sample_id, "title": sample.title}, "run_id": run_id, "reason": type(error).__name__}
        with self._lock:
            self._status = result


def serve(runner: DemoReplayRunner, token: str, host: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def _authorized(self) -> bool:
            return hmac.compare_digest(self.headers.get("X-ShieldChain-Nta-Replay-Token", ""), token)

        def _send(self, code: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if not self._authorized():
                self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            elif self.path == "/v1/demo-replay/status":
                self._send(HTTPStatus.OK, runner.status())
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:
            if not self._authorized():
                self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            elif self.path == "/v1/demo-replay/start":
                self._send(HTTPStatus.ACCEPTED, runner.start())
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def log_message(self, _format: str, *_args: object) -> None:
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description="ShieldChain allowlisted demo replay runner")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--pcap-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--host", default="172.18.0.1")
    parser.add_argument("--port", default=18082, type=int)
    args = parser.parse_args()
    token = os.environ.get("SHIELDCHAIN_NTA_REPLAY_RUNNER_TOKEN", "")
    if len(token) < 24:
        raise ValueError("SHIELDCHAIN_NTA_REPLAY_RUNNER_TOKEN must contain at least 24 characters")
    serve(DemoReplayRunner(manifest=args.manifest, pcap_root=args.pcap_root, runtime_root=args.runtime_root), token, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
