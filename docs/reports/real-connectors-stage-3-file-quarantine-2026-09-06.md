# 真实连接器第三阶段：限定文件隔离与恢复

## 结论

2026-09-06，学校服务器完成限定文件真实处置验收。链路为：Wazuh 规范化告警 → Qwen3-30B 多智能体调查 → 响应规划 → 人工接受计划 → 独立批准高风险工具 → 文件原子隔离 → 只读状态与 SHA-256 复核 → 恢复并再次核验。该链路使用无害标记文件，不包含恶意样本。

## 安全实现

- 告警 evidence 只携带 `file_id=demo-suspicious-marker`，不携带文件路径。
- 后端与端点执行器分别校验允许名单；模型不能生成路径、命令、URL 或凭据。
- 文件仅位于独立 Docker 命名卷 `shieldchain-file-response-lab`，主后端无权直接挂载该卷。
- Wazuh 桥和端点执行器只通过带令牌的 Unix Socket 通信，不开放宿主机 TCP 端口。
- 执行器拒绝符号链接、超过 10 MiB 的文件、路径型 ID、缺失或歧义状态。
- 隔离使用同卷 `os.replace` 原子移动，并将权限收紧为仅所有者可读；隔离、恢复前后均计算 SHA-256。
- `quarantine_file` 和 `restore_file` 注册为 high 风险写操作；计划接受不能替代逐工具人工审批。

## 实测结果

- 初始状态：`present`，52 字节，SHA-256 `5ef55b7e30f39f8265fca3acc6b4cb71892b020e7a6b0d69ec4c5a8c56697629`。
- Qwen 自主规划：`query_file_state → quarantine_file`，动作数 2，计划为 `proposed`。
- 查询动作：read_only，策略自动允许，执行与验证均成功。
- 隔离动作：high，策略返回 `approval_required`；人工批准后状态 `succeeded`，独立验证 `verified`。
- 恢复后：`present`，大小与 SHA-256 均与隔离前一致。
- 专项单元测试：23 passed。
- 正确的服务器可写临时副本完整套件：1247 passed, 33 skipped, 0 failed；临时副本已删除。

验收脚本：

```bash
docker compose -f compose.yaml -f compose.server.yaml -f compose.local-llm.yaml \
  exec -T -e PYTHONDONTWRITEBYTECODE=1 backend \
  sh -c 'cd /app/scripts && /opt/venv/bin/python \
  verify_wazuh_file_response_e2e.py --execute'
```

## 边界

这是真实的文件系统状态变更，但只发生在独立实验数据卷中的允许名单无害文件。它证明了响应规划、审批、执行、验证和恢复机制，不证明已经具备 Windows/Linux 生产终端任意文件隔离能力。接入生产 EDR 前仍需签名脚本、设备身份、真实文件哈希/路径映射、证据保全、双人审批、离线恢复和厂商 API 授权。
