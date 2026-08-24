from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "nta" / "nta_offline_pipeline.py"
)
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

    def test_phishing_alert_gets_email_credential_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(
                result / "suricata" / "eve.json",
                [
                    {
                        "event_type": "alert",
                        "alert": {
                            "signature": (
                                "ShieldChain POP3 phishing hexadecimal IP login link"
                            )
                        },
                    }
                ],
            )

            category, severity, mitre_ids, _, _ = nta.classify_findings(result)

            self.assertEqual(category, "钓鱼邮件与凭据诱导")
            self.assertEqual(severity, 9)
            self.assertIn("T1566.002", mitre_ids)

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

    def test_informational_ntlm_handshake_is_not_a_security_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(
                result / "suricata" / "eve.json",
                [
                    {
                        "event_type": "alert",
                        "alert": {
                            "signature": "ET INFO NTLM Session Setup Request - Negotiate",
                            "category": "Not Suspicious Traffic",
                        },
                    }
                ],
            )
            category, severity, mitre_ids, signatures, findings = nta.classify_findings(
                result
            )
            self.assertEqual(category, "未检出有效网络行为")
            self.assertEqual(severity, 3)
            self.assertEqual(mitre_ids, [])
            self.assertEqual(signatures, [])
            self.assertTrue(any("informational/decoder" in item for item in findings))

    def test_winrm_user_agent_is_contextual_not_a_security_alert(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(
                result / "suricata" / "eve.json",
                [
                    {
                        "event_type": "alert",
                        "alert": {
                            "signature_id": 2026850,
                            "signature": "ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement",
                            "category": "Potentially Bad Traffic",
                        },
                    }
                ],
            )
            category, severity, mitre_ids, signatures, findings = nta.classify_findings(
                result
            )
            self.assertEqual(category, "未检出有效网络行为")
            self.assertEqual(severity, 3)
            self.assertEqual(mitre_ids, [])
            self.assertEqual(signatures, [])
            self.assertTrue(any("contextual observation" in item for item in findings))

            event = nta.build_event(Path("winrm.pcap"), "a" * 64, result, 0, 0)
            self.assertEqual(event["evidence"]["suricata_alert_count"], 0)
            self.assertEqual(
                event["evidence"]["suricata_contextual_observation_count"], 1
            )
            self.assertEqual(
                event["evidence"]["suricata_ignored_informational_event_count"], 0
            )

    def test_irc_command_sequence_is_aggregated_as_command_and_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            rows = []
            for command in ("USER", "NICK", "JOIN", "PRIVMSG"):
                rows.extend(
                    {
                        "event_type": "alert",
                        "alert": {"signature": f"ET CHAT IRC {command} command"},
                    }
                    for _ in range(3)
                )
            write_json_lines(result / "suricata" / "eve.json", rows)

            category, severity, mitre_ids, _, findings = nta.classify_findings(result)

            self.assertEqual(category, "疑似 IRC 命令控制")
            self.assertEqual(severity, 10)
            self.assertIn("T1071", mitre_ids)
            self.assertTrue(any("Aggregated IRC" in item for item in findings))

    def test_single_irc_command_type_stays_generic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(
                result / "suricata" / "eve.json",
                [
                    {
                        "event_type": "alert",
                        "alert": {"signature": "ET CHAT IRC PONG response"},
                    }
                    for _ in range(12)
                ],
            )

            category, _, _, _, _ = nta.classify_findings(result)

            self.assertEqual(category, "Suricata 安全规则告警")

    def test_large_generic_script_posts_are_http_command_channel_not_webshell(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(
                result / "zeek" / "http.log",
                [
                    {
                        "method": "POST",
                        "host": "unfamiliar.example",
                        "uri": "/ajax.php",
                        "request_body_len": 9000,
                        "response_body_len": 25,
                    }
                    for _ in range(3)
                ],
            )
            write_json_lines(result / "zeek" / "conn.log", [])
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, mitre_ids, _, findings = nta.classify_findings(result)

            self.assertEqual(category, "疑似 HTTP 命令控制或数据外传")
            self.assertEqual(severity, 10)
            self.assertIn("T1071.001", mitre_ids)
            self.assertIn("T1041", mitre_ids)
            self.assertTrue(any("command-channel" in item for item in findings))

    def test_repeated_normal_webmail_posts_are_not_webshell(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(
                result / "zeek" / "http.log",
                [
                    {
                        "method": "POST",
                        "uri": "/mail/SendMessageLight.aspx",
                        "user_agent": "Mozilla/5.0",
                        "request_body_len": 3487,
                        "response_body_len": 107042,
                    }
                    for _ in range(15)
                ],
            )
            write_json_lines(result / "zeek" / "conn.log", [])
            write_json_lines(result / "zeek" / "dns.log", [])

            category, _, mitre_ids, _, _ = nta.classify_findings(result)

            self.assertEqual(category, "网络行为待研判")
            self.assertNotIn("T1505.003", mitre_ids)

    def test_udp_on_suspicious_port_is_not_reverse_connection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(
                result / "zeek" / "http.log",
                [{"method": "GET", "uri": "/"}],
            )
            write_json_lines(
                result / "zeek" / "conn.log",
                [
                    {
                        "proto": "udp",
                        "id.resp_p": 5555,
                        "duration": 10,
                        "orig_bytes": 100,
                        "resp_bytes": 100,
                    }
                ],
            )
            write_json_lines(result / "zeek" / "dns.log", [])

            category, _, _, _, _ = nta.classify_findings(result)

            self.assertEqual(category, "网络行为待研判")

    def test_bidirectional_long_tcp_connection_on_shell_port_is_suspicious(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(result / "zeek" / "http.log", [])
            write_json_lines(
                result / "zeek" / "conn.log",
                [
                    {
                        "proto": "tcp",
                        "id.resp_p": 4444,
                        "duration": 10,
                        "orig_bytes": 120,
                        "resp_bytes": 80,
                    }
                ],
            )
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, _, _, _ = nta.classify_findings(result)

            self.assertEqual(category, "疑似反弹连接")
            self.assertEqual(severity, 9)

    def test_high_rejection_destination_fanout_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(result / "zeek" / "http.log", [])
            write_json_lines(
                result / "zeek" / "conn.log",
                [
                    {
                        "id.orig_h": "10.0.0.5",
                        "id.resp_h": f"192.0.2.{index}",
                        "id.resp_p": 445,
                        "proto": "tcp",
                        "conn_state": "S0",
                    }
                    for index in range(1, 201)
                ],
            )
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, mitre_ids, _, findings = nta.classify_findings(result)

            self.assertEqual(category, "疑似扫描与僵尸网络传播")
            self.assertEqual(severity, 9)
            self.assertIn("T1046", mitre_ids)
            self.assertTrue(any("high-rejection" in item for item in findings))

    def test_periodic_high_rejection_fanout_is_detected_as_beaconing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(result / "zeek" / "http.log", [])
            fanout = [
                {
                    "id.orig_h": "10.0.0.6",
                    "id.resp_h": f"203.0.113.{index}",
                    "id.resp_p": 25,
                    "proto": "tcp",
                    "conn_state": "S0",
                    "ts": index,
                }
                for index in range(1, 201)
            ]
            beacon = [
                {
                    "id.orig_h": "10.0.0.6",
                    "id.resp_h": "198.51.100.10",
                    "id.resp_p": 25,
                    "proto": "tcp",
                    "conn_state": "S0",
                    "ts": 1000 + index * 15,
                }
                for index in range(13)
            ]
            write_json_lines(result / "zeek" / "conn.log", fanout + beacon)
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, mitre_ids, _, findings = nta.classify_findings(result)

            self.assertEqual(category, "疑似周期信标与僵尸网络活动")
            self.assertEqual(severity, 10)
            self.assertIn("T1071", mitre_ids)
            self.assertTrue(any("periodic connection" in item for item in findings))

    def test_high_fanout_udp_multiport_behavior_is_detected_as_p2p(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = Path(temp)
            write_json_lines(result / "suricata" / "eve.json", [])
            write_json_lines(result / "zeek" / "http.log", [])
            write_json_lines(
                result / "zeek" / "conn.log",
                [
                    {
                        "id.orig_h": "10.0.0.8",
                        "id.resp_h": f"198.51.100.{index % 100}",
                        "id.resp_p": 10000 + index % 50,
                        "proto": "udp",
                        "conn_state": "SF",
                    }
                    for index in range(200)
                ],
            )
            write_json_lines(result / "zeek" / "dns.log", [])

            category, severity, mitre_ids, _, findings = nta.classify_findings(result)

            self.assertEqual(category, "疑似 P2P/UDP 僵尸网络")
            self.assertEqual(severity, 9)
            self.assertIn("T1071", mitre_ids)
            self.assertTrue(any("UDP/P2P" in item for item in findings))


if __name__ == "__main__":
    unittest.main()
