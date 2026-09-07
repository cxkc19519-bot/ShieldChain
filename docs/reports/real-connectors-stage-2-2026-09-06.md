# 真实连接器第二阶段：演示端点隔离与恢复

## 阶段目标

在不修改服务器宿主机网络、也不赋予主后端网络管理权限的前提下，为 Wazuh 演示 Agent `002` 建立可审批、可验证、可自动回滚的端点隔离闭环。

## 实现结构

- 主后端只产生经过注册表约束的 `query_endpoint_state`、`isolate_endpoint`、`restore_endpoint` 请求。
- 非 root Wazuh 执行器继续使用专用只读 API 身份核对 Agent `002` 的真实元数据，并通过第二个 Unix Socket 调用端点执行器。
- 端点执行器只共享演示 Agent 容器的网络命名空间，仅保留 `NET_ADMIN` capability。
- nftables 状态集合使用 60 秒至 24 小时 TTL；到期自动恢复网络。
- 隔离期间放行回环、已有连接和 TCP 1514/1515，避免切断 Wazuh 管理链路。

## 安全边界

- Agent ID 固定为 `002`，越权目标拒绝。
- 接口只接受固定 JSON 字段，不接受 URL、命令、脚本或 nftables 表达式。
- 隔离与恢复均为高风险写动作，需要计划接受后再逐动作人工审批。
- 当前隔离对象是容器化 Linux 演示 Agent；不能将结果外推为 Windows EDR 或生产终端隔离能力。

## 验收记录

代码侧已通过 Python 编译检查、差异检查和本次变更 Ruff 检查。连接器相关测试为 `32 passed`。Windows 临时环境完整后端测试为 `1242 passed, 26 skipped, 9 failed`；9 项失败均位于既有中文知识库文件哈希/编码和 MCP 依赖错误文本断言，不涉及本阶段改动。本地一次性测试环境随后已删除，测试源码已同步到服务器。

服务器于 2026-09-06 完成实机验收：

- `endpoint-response-executor`、`wazuh-response-executor`、`backend`、`frontend` 均为 healthy。
- 运行中后端注册 `query_endpoint_state`、`isolate_endpoint`、`restore_endpoint`，其中隔离和恢复风险级别为 high。
- Agent `002` 状态依次为 `connected → isolated → connected`，隔离期间 Wazuh 状态保持 `Active`。
- Agent `001` 请求被白名单拒绝。
- 第二次隔离未调用恢复接口，60 秒 TTL 到期后自动返回 `connected`，Agent 仍为 `Active`。
- 完整应用控制面验收已通过：规范化 Wazuh 告警入库后，Qwen3-30B 自主选择 `isolate_endpoint`；另一次运行选择“先查询、再隔离”的依赖链。计划接受后仍停在逐动作人工审批；批准后执行状态为 `succeeded`、验证为 `verified`，60 秒后独立查询恢复为 `connected`。
- 后端和 Wazuh 桥为只读根文件系统且无额外 capability；只有端点执行器具备 `CAP_NET_ADMIN`，网络模式绑定到演示 Agent 容器。

验收命令：

```bash
docker exec -i shieldchain-backend-1 python - --execute --verify-ttl \
  < scripts/verify_endpoint_response_e2e.py
```

首次部署时服务器 Docker 镜像仓库代理不可用，因此先使用带 `pre-stage2` 备份标签的离线镜像补丁完成实机验收。随后建立 `127.0.0.1:17897 → SSH 反向隧道 → 本机 Clash 7897` 链路，镜像站探测返回正常的 HTTP 401，并成功完成标准 Compose 重建。切换到标准镜像后再次通过即时“查询—隔离—恢复—越权拒绝”验收。

完整控制面验收命令：

```bash
docker compose -f compose.yaml -f compose.server.yaml -f compose.local-llm.yaml \
  exec -T -e PYTHONDONTWRITEBYTECODE=1 backend \
  sh -c 'cd /app/scripts && /opt/venv/bin/python \
  verify_wazuh_endpoint_control_plane_e2e.py --execute --ttl 60'
```
