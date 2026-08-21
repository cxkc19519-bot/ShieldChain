#!/usr/bin/env python3
"""Post minimized, offline NTA analysis evidence to ShieldChain's review inbox."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def normalize_payload(value: dict[str, object]) -> dict[str, object]:
    payload = dict(value)
    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        payload["evidence"] = {
            str(key): item
            if item is None or isinstance(item, (str, int, float, bool))
            else json.dumps(item, ensure_ascii=False, separators=(",", ":"))
            for key, item in evidence.items()
        }
    return payload


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    token = os.environ.get("WAZUH_WEBHOOK_TOKEN", "")
    if not token:
        return 3
    endpoint = os.environ.get("SHIELDCHAIN_NTA_INGEST_ENDPOINT", "http://backend:8000/api/v1/integrations/wazuh/alerts")
    failures = 0
    for raw_line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        try:
            payload = json.dumps(
                normalize_payload(json.loads(raw_line)), ensure_ascii=False
            ).encode("utf-8")
            request = Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json", "X-ShieldChain-Wazuh-Token": token},
                method="POST",
            )
            with urlopen(request, timeout=15) as response:
                if not 200 <= response.status < 300:
                    failures += 1
        except (OSError, ValueError, TypeError, HTTPError, URLError):
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
