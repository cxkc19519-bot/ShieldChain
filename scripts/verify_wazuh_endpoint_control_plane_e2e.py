"""Verify alert -> agents -> approvals -> Agent 002 isolation -> TTL restore."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime

from shieldchain.tools.wazuh_connector import WazuhHttpAdapter
from verify_wazuh_response_e2e import compact, request_json

TEST_AGENT_ID = "002"


def executor() -> WazuhHttpAdapter:
    return WazuhHttpAdapter(
        base_url=os.environ["RESPONSE_WAZUH_EXECUTOR_URL"],
        token=os.environ["RESPONSE_WAZUH_EXECUTOR_TOKEN"],
    )


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
        raise RuntimeError("WAZUH_WEBHOOK_TOKEN is not configured")
    initial = executor()._post("/v1/wazuh/agent/query", {"agent_id": TEST_AGENT_ID})
    if initial.get("isolation_status") != "connected":
        raise RuntimeError("Agent 002 must be connected before verification")
    compact("precondition_checked", {"agent_id": TEST_AGENT_ID, "isolation_status": "connected"})

    now = datetime.now(UTC)
    nonce = now.strftime("%Y%m%dT%H%M%S%fZ")
    alert = request_json(
        args.base_url,
        "POST",
        "/integrations/wazuh/alerts",
        {
            "external_id": f"shieldchain-endpoint-e2e-{nonce}",
            "occurred_at": now.isoformat(),
            "severity": 15,
            "rule_id": f"SC-ENDPOINT-E2E-{nonce}",
            "title": "受控验收：已确认恶意进程，需要隔离受影响端点",
            "agent_id": TEST_AGENT_ID,
            "agent_name": "shieldchain-server-demo",
            "mitre_ids": ["T1059", "T1105"],
            "process_name": "shieldchain-benign-verification-marker",
            "evidence": {
                "finding": "confirmed_compromise",
                "containment": "endpoint_isolation_required",
                "verification_scope": "allowlisted-demo-agent-only",
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
        {"run_id": run_id, "model": report.get("model"), "plan": plan_ref},
    )
    if not run_id or not isinstance(plan_ref, dict) or plan_ref.get("status") != "proposed":
        raise RuntimeError("investigation did not produce a proposed response plan")

    plan_id = str(plan_ref["plan_id"])
    plan = request_json(args.base_url, "GET", f"/response-plans/{plan_id}")
    revisions = plan.get("revisions")
    if not isinstance(revisions, list) or not revisions:
        raise RuntimeError("response plan has no revision")
    latest = revisions[-1]
    actions = latest.get("actions") if isinstance(latest, dict) else None
    if not isinstance(actions, list) or not 1 <= len(actions) <= 2:
        raise RuntimeError(f"expected a bounded endpoint plan, got: {actions}")
    names = [item.get("tool_name") for item in actions]
    if names not in (["isolate_endpoint"], ["query_endpoint_state", "isolate_endpoint"]):
        raise RuntimeError(f"model selected an unexpected endpoint plan: {actions}")
    if any(item.get("target") != TEST_AGENT_ID for item in actions):
        raise RuntimeError(f"model escaped the controlled Agent 002 target: {actions}")
    if len(actions) == 2 and actions[1].get("depends_on") != [actions[0].get("id")]:
        raise RuntimeError("isolation must depend on the preceding state query")
    compact("plan_checked", {"plan_id": plan_id, "tools": names, "target": TEST_AGENT_ID})

    accepted = request_json(
        args.base_url,
        "POST",
        f"/response-plans/{plan_id}/accept",
        {
            "current_revision": plan["current_revision"],
            "reason": "人工接受 Agent 002 的 60 秒受控隔离验收计划",
        },
    )
    calls = accepted.get("calls")
    if not isinstance(calls, list) or len(calls) != len(actions):
        raise RuntimeError("accepted plan did not create the planned trusted tool calls")
    isolate_calls = [item for item in calls if item.get("tool_name") == "isolate_endpoint"]
    if len(isolate_calls) != 1:
        raise RuntimeError(f"accepted plan did not expose one isolation call: {calls}")
    call_id = str(isolate_calls[0]["call_id"])
    compact("plan_accepted", {"plan_id": plan_id, "call_id": call_id})

    approved = request_json(
        args.base_url,
        "POST",
        f"/tools/calls/{call_id}/approval",
        {
            "outcome": "approved",
            "reason": "人工批准允许名单内 Agent 002 的临时隔离验收",
        },
    )
    compact("tool_approved", approved)

    trace = request_json(args.base_url, "GET", f"/tools/runs/{run_id}/calls")
    trace_calls = trace.get("calls")
    if not isinstance(trace_calls, list) or len(trace_calls) != len(actions):
        raise RuntimeError("trusted tool trace is missing")
    matching = [item for item in trace_calls if item.get("tool_name") == "isolate_endpoint"]
    if len(matching) != 1:
        raise RuntimeError(f"trusted isolation trace is missing: {trace_calls}")
    item = matching[0]
    if item.get("target") != TEST_AGENT_ID or item.get("verification_outcome") != "verified":
        raise RuntimeError("endpoint isolation was not independently verified")
    compact("execution_verified", trace)

    observed = executor()._post("/v1/wazuh/agent/query", {"agent_id": TEST_AGENT_ID})
    if observed.get("isolation_status") != "isolated":
        raise RuntimeError("Agent 002 is not isolated after approved execution")
    compact("isolation_observed", {"agent_id": TEST_AGENT_ID, "isolation_status": "isolated"})

    print(f"Waiting {args.ttl + 5}s for endpoint TTL recovery...", flush=True)
    time.sleep(args.ttl + 5)
    restored = executor()._post("/v1/wazuh/agent/query", {"agent_id": TEST_AGENT_ID})
    if restored.get("isolation_status") != "connected":
        raise RuntimeError("Agent 002 did not recover after TTL")
    compact("ttl_restore_verified", {"agent_id": TEST_AGENT_ID, "isolation_status": "connected"})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"stage": "failed", "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise
