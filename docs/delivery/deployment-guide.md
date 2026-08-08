# 部署手册

> 文档状态：当前参考（更新于 2026-08-08）。Docker 与 Wazuh 已在学校服务器环境实际使用；本地 30B 模型仍受权重下载和共享 GPU 可用性约束。

## 基础 Compose

```bash
docker compose up -d --build
```

前端绑定 `127.0.0.1:8080`，后端仅在 Compose 内部网络提供服务。数据库、知识库和助手数据位于持久化卷；`docker compose down` 默认保留数据。

## 服务器覆盖

```bash
docker compose -f compose.yaml -f compose.server.yaml up -d --build
```

服务器工作目录限定为 `/home/user/jhk/shieldchain`。`.env` 位于服务器私有目录，不进入镜像和版本库。

从本地浏览器访问服务器前端时使用 SSH 本地端口转发，不需要在服务器安装桌面环境：

```powershell
ssh -i C:\Users\a\.ssh\shieldchain_lab_ed25519 -p 1100 `
  -L 18080:127.0.0.1:8080 jhk@121.48.164.89
```

然后访问 `http://127.0.0.1:18080`。

## 本地模型覆盖

```bash
LOCAL_LLM_CACHE_DIR=/home/user/jhk/huggingface \
docker compose -f compose.yaml -f compose.local-llm.yaml up -d
```

覆盖配置启动 vLLM `Qwen/Qwen3-30B-A3B-Instruct-2507-FP8`，模型服务绑定服务器回环地址 `127.0.0.1:8001`，后端容器通过 `http://local-llm:8000/v1` 访问。

当前参数面向两张 RTX 4090：流水线并行 2、最大上下文 16384、最大并发序列 4。启动前必须确认：

- 权重下载完整；
- NVIDIA Container Toolkit 可用；
- 两张 GPU 有足够空闲显存；
- 已与共享服务器其他用户协调资源。

不得终止或修改其他用户 GPU 进程。如果流水线并行不受模型实现支持，再在独立验证后评估张量并行和禁用自定义 all-reduce 的备用方案。

## Wazuh

Wazuh Manager、Indexer/OpenSearch 和 Dashboard 运行在服务器 Docker 环境。Windows Wazuh Agent 或离线数据集向 Manager 提供遥测；`scripts/wazuh/custom-shieldchain` 将满足条件的告警只读转发到 ShieldChain。

## 代理

校园服务器无法直接访问部分镜像仓库时，可通过 SSH 反向隧道使用本机 Clash 代理。代理只用于镜像和模型下载，不应成为生产请求链路的一部分。完成下载后关闭临时隧道，并确认 Docker 代理配置不会暴露到外部网络。

## 上线前检查

- 更换所有默认密码与 Token；
- 限制监听地址并配置 TLS、身份认证和最小权限；
- 备份数据库、知识库、助手会话和 Wazuh 索引；
- 验证恢复、磁盘容量、日志轮转和告警留存；
- 对镜像执行漏洞扫描并固定摘要；
- 对真实处置工具单独进行审批、幂等和回滚验收。
