"""Verify a bounded Wazuh file alert through planning, approval and recovery."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime

from shieldchain.tools.wazuh_connector import WazuhHttpAdapter
from verify_wazuh_response_e2e import compact, request_json

AGENT_ID = "002"
FILE_ID = "demo-suspicious-marker"


def executor() -> WazuhHttpAdapter:
    return WazuhHttpAdapter(
        base_url=os.environ["RESPONSE_WAZUH_EXECUTOR_URL"],
        token=os.environ["RESPONSE_WAZUH_EXECUTOR_TOKEN"],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        parser.error("refusing a mutating verification without --execute")
    token = os.environ.get("WAZUH_WEBHOOK_TOKEN", "")
    if not token:
        raise RuntimeError("WAZUH_WEBHOOK_TOKEN is not configured")

    initial = executor()._post(
        "/v1/wazuh/file/query", {"agent_id": AGENT_ID, "file_id": FILE_ID}
    )
    if initial.get("file_status") != "present":
        raise RuntimeError("allowlisted marker must be present before verification")
    digest = str(initial.get("sha256"))
    compact("file_precondition_checked", initial)

    now = datetime.now(UTC)
    nonce = now.strftime("%Y%m%dT%H%M%S%fZ")
    alert = request_json(
        args.base_url,
        "POST",
        "/integrations/wazuh/alerts",
        {
            "external_id": f"shieldchain-file-e2e-{nonce}",
            "occurred_at": now.isoformat(),
            "severity": 15,
            "rule_id": f"SC-FILE-E2E-{nonce}",
            "title": "受控验收：已确认恶意文件，需要隔离限定文件",
            "agent_id": AGENT_ID,
            "agent_name": "shieldchain-server-demo",
            "mitre_ids": ["T1105"],
            "process_name": "shieldchain-benign-verification-marker",
            "evidence": {
                "finding": "confirmed_malicious_file",
                "file_id": FILE_ID,
                "sha256": digest,
                "verification_scope": "allowlisted-benign-marker-only",
            },
        },
        token=token,
    )
    review_case = alert.get("review_case")
    if not isinstance(review_case, dict) or not review_case.get("id"):
        raise RuntimeError("ingested file alert did not create a review case")
    case_id = str(review_case["id"])
    compact("file_alert_ingested", {"alert_id": alert["id"], "case_id": case_id})

    report = request_json(
        args.base_url,
        "POST",
        f"/integrations/wazuh/cases/{case_id}/investigate",
        {"rule_ttl_seconds": 60},
        timeout=1200,
    )
    run_id = str(report.get("run_id") or "")
    plan_ref = report.get("response_plan")
    compact("file_investigation_complete", {"run_id": run_id, "model": report.get("model"), "plan": plan_ref})
    if not run_id or not isinstance(plan_ref, dict) or plan_ref.get("status") != "proposed":
        raise RuntimeError("investigation did not produce a proposed file plan")

    plan_id = str(plan_ref["plan_id"])
    plan = request_json(args.base_url, "GET", f"/response-plans/{plan_id}")
    revisions = plan.get("revisions")
    if not isinstance(revisions, list) or not revisions:
        raise RuntimeError("file response plan has no revision")
    actions = revisions[-1].get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= 2:
        raise RuntimeError(f"expected a bounded file plan, got: {actions}")
    names = [item.get("tool_name") for item in actions]
    if names not in (["quarantine_file"], ["query_file_state", "quarantine_file"]):
        raise RuntimeError(f"model selected an unexpected file plan: {actions}")
    if any(item.get("target") != AGENT_ID for item in actions):
        raise RuntimeError("file plan escaped Agent 002")
    compact("file_plan_checked", {"plan_id": plan_id, "tools": names, "target": AGENT_ID, "file_id": FILE_ID})

    accepted = request_json(
        args.base_url,
        "POST",
        f"/response-plans/{plan_id}/accept",
        {"current_revision": plan["current_revision"], "reason": "人工接受限定标记文件的受控隔离计划"},
    )
    calls = accepted.get("calls")
    if not isinstance(calls, list) or len(calls) != len(actions):
        raise RuntimeError("accepted plan did not create the planned file calls")
    quarantine_calls = [item for item in calls if item.get("tool_name") == "quarantine_file"]
    if len(quarantine_calls) != 1:
        raise RuntimeError(f"one quarantine approval call was expected: {calls}")
    call_id = str(quarantine_calls[0]["call_id"])
    compact("file_plan_accepted", {"plan_id": plan_id, "call_id": call_id})

    approved = request_json(
        args.base_url,
        "POST",
        f"/tools/calls/{call_id}/approval",
        {"outcome": "approved", "reason": "人工批准限定文件 ID 的受控隔离验收"},
    )
    compact("file_tool_approved", approved)
    trace = request_json(args.base_url, "GET", f"/tools/runs/{run_id}/calls")
    matching = [item for item in trace.get("calls", []) if item.get("tool_name") == "quarantine_file"]
    if len(matching) != 1 or matching[0].get("verification_outcome") != "verified":
        raise RuntimeError(f"file quarantine was not independently verified: {trace}")
    compact("file_quarantine_verified", trace)

    quarantined = executor()._post(
        "/v1/wazuh/file/query", {"agent_id": AGENT_ID, "file_id": FILE_ID}
    )
    if quarantined.get("file_status") != "quarantined" or quarantined.get("sha256") != digest:
        raise RuntimeError("quarantined file state or digest is incorrect")
    restored = executor()._post(
        "/v1/wazuh/file/restore", {"agent_id": AGENT_ID, "file_id": FILE_ID}
    )
    if restored.get("file_status") != "present" or restored.get("sha256") != digest:
        raise RuntimeError("file recovery did not preserve the original digest")
    compact("file_recovery_verified", restored)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"stage": "failed", "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise
