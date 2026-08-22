from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "nta" / "nta_offline_pipeline.py"
SPEC = importlib.util.spec_from_file_location("nta_offline_pipeline", MODULE_PATH)
assert SPEC and SPEC.loader
nta = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nta)


def write_json_lines(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


class ClassifyFindingsTests(unittest.TestCase):
    def test_sql_injection_alert_gets_database_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(
                result / "suricata" / "eve.json",
                [
                    {
                        "event_type": "alert",
                        "alert": {
                            "signature": (
                                "ShieldChain MySQL nested UNION SQL injection "
                                "user extraction"
                            ),
                            "category": "Web Application Attack",
                        },
                    }
                ],
            )

            category, severity, mitre_ids, signatures, _ = nta.classify_findings(result)

            self.assertEqual(category, "数据库攻击与数据提取")
            self.assertEqual(severity, 10)
            self.assertIn("T1190", mitre_ids)
            self.assertEqual(len(signatures), 1)

    def test_framework_exploit_alert_gets_vulnerability_category(self) -> None:
        for signature in (
            "ShieldChain ThinkPHP filter remote code execution",
            "ShieldChain Shiro rememberMe deserialization exploit",
            "ET WEB_SERVER Possible CVE Struts Exploit Attempt",
            "ET WEB_SERVER Possible Fastjson Attack",
        ):
            with (
                self.subTest(signature=signature),
                tempfile.TemporaryDirectory() as temp,
            ):
                result = Path(temp)
                write_json_lines(
                    result / "suricata" / "eve.json",
                    [
                        {
                            "event_type": "alert",
                            "alert": {"signature": signature},
                        }
                    ],
                )
                category, severity, mitre_ids, _, _ = nta.classify_findings(result)
                self.assertEqual(category, "漏洞利用")
                self.assertEqual(severity, 11)
                self.assertIn("T1190", mitre_ids)

    def test_command_form_alert_gets_command_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(
                result / "suricata" / "eve.json",
                [
                    {
                        "event_type": "alert",
                        "alert": {
                            "signature": "ShieldChain certutil download command form"
                        },
                    }
                ],
            )
            category, severity, mitre_ids, _, _ = nta.classify_findings(result)
            self.assertEqual(category, "命令执行")
            self.assertEqual(severity, 11)
            self.assertIn("T1059", mitre_ids)

    def test_repeated_small_script_commands_get_webshell_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(
                result / "zeek" / "http.log",
                [
                    {
                        "method": "POST",
                        "uri": "/gateway.jspx",
                        "request_body_len": 64,
                        "response_body_len": 700,
                    }
                    for _ in range(8)
                ],
            )
            write_json_lines(result / "zeek" / "conn.log", [])
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, mitre_ids, _, findings = nta.classify_findings(result)

            self.assertEqual(category, "疑似 WebShell 交互")
            self.assertEqual(severity, 11)
            self.assertIn("T1505.003", mitre_ids)
            self.assertTrue(any("WebShell-like" in item for item in findings))

    def test_single_benign_report_post_with_huge_response_stays_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(
                result / "zeek" / "http.log",
                [
                    {
                        "method": "POST",
                        "uri": "/console.php",
                        "request_body_len": 17,
                        "response_body_len": 42442,
                    }
                ],
            )
            write_json_lines(result / "zeek" / "conn.log", [])
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, mitre_ids, _, _ = nta.classify_findings(result)

            self.assertEqual(category, "网络行为待研判")
            self.assertEqual(severity, 5)
            self.assertNotIn("T1505.003", mitre_ids)


if __name__ == "__main__":
    unittest.main()
