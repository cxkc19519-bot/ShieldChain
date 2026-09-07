#!/usr/bin/env python3
"""Run a controlled Wazuh -> agents -> approval -> firewall verification.

This verifier is intentionally restricted to the RFC 5737 TEST-NET-3 address
203.0.113.25.  It reads the webhook token from the process environment and
never prints it.  A mutating run requires the explicit ``--execute`` flag.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

from shieldchain.tools.firewall_connector import NftablesHttpAdapter


TEST_TARGET = "203.0.113.25"


def request_json(
    base_url: str,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    *,
    token: str | None = None,
    timeout: int = 900,
) -> dict[str, object]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-ShieldChain-Wazuh-Token"] = token
    req = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed: HTTP {error.code}: {detail}") from error


def compact(label: str, value: dict[str, object]) -> None:
    print(json.dumps({"stage": label, **value}, ensure_ascii=False, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--ttl", type=int, default=60, choices=range(60, 301))
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        parser.error("refusing a mutating verification without --execute")

    token = os.environ.get("WAZUH_WEBHOOK_TOKEN", "")
    if not token:
        raise RuntimeError("WAZUH_WEBHOOK_TOKEN is not configured in the backend container")

    now = datetime.now(UTC)
    external_id = "shieldchain-e2e-" + now.strftime("%Y%m%dT%H%M%S%fZ")
    rule_id = "SC-E2E-" + now.strftime("%Y%m%dT%H%M%S%fZ")
    alert = request_json(
        args.base_url,
        "POST",
        "/integrations/wazuh/alerts",
        {
            "external_id": external_id,
            "occurred_at": now.isoformat(),
            "severity": 14,
            "rule_id": rule_id,
            "title": "受控验收：测试网段来源触发多智能体调查",
            "agent_id": "shieldchain-e2e",
            "agent_name": "ShieldChain controlled verifier",
            "mitre_ids": ["T1110"],
            "process_name": "sshd",
            "source_ip": TEST_TARGET,
            "destination_ip": "192.0.2.10",
            "destination_port": 22,
            "evidence": {
                "verification_scope": "RFC5737-only",
                "failed_attempts": 27,
                "authorized_by": "operator-e2e-verification",
            },
        },
        token=token,
    )
    review_case = alert.get("review_case")
    if not isinstance(review_case, dict) or not review_case.get("id"):
        raise RuntimeError("ingested alert did not create a review case")
    case_id = str(review_case["id"])
    compact("alert_ingested", {"alert_id": alert["id"], "case_id": case_id})

    report = request_json(
        args.base_url,
        "POST",
        f"/integrations/wazuh/cases/{case_id}/investigate",
        {"rule_ttl_seconds": args.ttl},
        timeout=1200,
    )
    run_id = str(report.get("run_id") or "")
    plan_ref = report.get("response_plan")
    compact(
        "investigation_complete",
        {
            "run_id": run_id,
            "model": report.get("model"),
            "plan": plan_ref,
            "closure": report.get("closure"),
        },
    )
    if not run_id or not isinstance(plan_ref, dict):
        raise RuntimeError("investigation did not return a run and response plan")
    if plan_ref.get("status") != "proposed" or plan_ref.get("action_count") != 1:
        raise RuntimeError("model did not produce the single permitted controlled action")

    plan_id = str(plan_ref["plan_id"])
    plan = request_json(args.base_url, "GET", f"/response-plans/{plan_id}")
    revisions = plan.get("revisions")
    if not isinstance(revisions, list) or not revisions:
        raise RuntimeError("response plan has no revision")
    latest = revisions[-1]
    actions = latest.get("actions") if isinstance(latest, dict) else None
    if not isinstance(actions, list) or len(actions) != 1 or actions[0].get("target") != TEST_TARGET:
        raise RuntimeError("response plan target escaped the controlled test address")
    compact(
        "plan_checked",
        {
            "plan_id": plan_id,
            "revision": plan["current_revision"],
            "target": actions[0]["target"],
            "tool": actions[0]["tool_name"],
        },
    )

    accepted = request_json(
        args.base_url,
        "POST",
        f"/response-plans/{plan_id}/accept",
        {
            "current_revision": plan["current_revision"],
            "reason": "受控端到端验收：仅允许 RFC 5737 测试地址，TTL 后自动清理",
        },
    )
    calls = accepted.get("calls")
    if not isinstance(calls, list) or len(calls) != 1:
        raise RuntimeError("accepted plan did not create exactly one trusted tool call")
    call_id = str(calls[0]["call_id"])
    compact("plan_accepted", {"plan_id": plan_id, "call_id": call_id, "status": calls[0]["status"]})

    approved = request_json(
        args.base_url,
        "POST",
        f"/tools/calls/{call_id}/approval",
        {
            "outcome": "approved",
            "reason": "人工批准受控 TEST-NET 地址的 60 秒临时规则验收",
        },
    )
    compact("tool_approved", approved)

    trace = request_json(args.base_url, "GET", f"/tools/runs/{run_id}/calls")
    compact("execution_verified", trace)
    trace_calls = trace.get("calls")
    if not isinstance(trace_calls, list) or len(trace_calls) != 1:
        raise RuntimeError("trusted tool trace is missing")
    item = trace_calls[0]
    if item.get("target") != TEST_TARGET or item.get("verification_outcome") != "verified":
        raise RuntimeError("controlled firewall execution was not verified")

    print(f"Waiting {args.ttl + 5}s for executor TTL cleanup...", flush=True)
    time.sleep(args.ttl + 5)
    executor = NftablesHttpAdapter(
        base_url=os.environ["RESPONSE_FIREWALL_EXECUTOR_URL"],
        token=os.environ["RESPONSE_FIREWALL_EXECUTOR_TOKEN"],
    )
    state = executor._post("/v1/firewall/query", {"target_ip": TEST_TARGET})
    if state.get("firewall_status") != "not_blocked":
        raise RuntimeError("controlled firewall rule did not expire after its TTL")
    compact(
        "ttl_cleanup_verified",
        {
            "target": TEST_TARGET,
            "ttl_seconds": args.ttl,
            "firewall_status": state["firewall_status"],
        },
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"stage": "failed", "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise
