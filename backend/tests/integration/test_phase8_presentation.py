import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_unfinished_presentation_and_video_are_planned_but_not_committed() -> None:
    manifest = json.loads((ROOT / "delivery" / "manifest.json").read_text("utf-8"))
    artifacts = {item["id"]: item for item in manifest["artifacts"]}
    for artifact_id in ("slides", "video"):
        artifact = artifacts[artifact_id]
        assert artifact["status"] == "planned"
        assert not (ROOT / artifact["path"]).exists()


def test_project_summary_matches_current_product_boundaries() -> None:
    summary = (ROOT / "docs" / "delivery" / "project-summary.md").read_text(
        encoding="utf-8"
    )
    for evidence in (
        "Wazuh 高风险告警接收",
        "七个专业角色",
        "事件、告警、漏洞、弱密码四类 MCP",
        "不自动执行真实处置",
        "真实生产网络、镜像流量和大规模并发仍需授权环境验收",
        "Remotion 视频工程、比赛 MP4 和相关测试",
    ):
        assert evidence in summary
