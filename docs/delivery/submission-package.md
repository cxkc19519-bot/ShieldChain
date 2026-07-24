# ShieldChain 比赛提交包

最终提交包为 `delivery/shieldchain-submission.zip`，由版本控制中的文件确定性构建；SHA-256 校验见 `delivery/submission-files.sha256`。

## 内容

- 后端源码、迁移、锁定依赖和测试。
- 前端源码、锁文件、构建配置和测试。
- Phase 2–8 Windows smoke、完整验证与打包脚本。
- 需求、架构、操作、交付、报告和逐日开发日志。
- Docker/Compose/CI/供应链静态合同。
- 10 页可编辑 PPTX、3 分钟 1080p MP4、分镜字幕和 Remotion 工程。

打包器只读取 `git ls-files`，明确排除自身、校验和、`.env`、虚拟环境、`node_modules`、渲染临时目录和运行数据库。ZIP 内路径使用 `/`，文件按路径排序并使用固定时间戳，便于复现。

## 复现

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\run-phase8-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\build-phase8-package.ps1
Get-FileHash -Algorithm SHA256 delivery\shieldchain-submission.zip
```

最终完整门禁使用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify.ps1
```

## 验收状态

- Windows 完整门禁：通过；后端 `1037 passed, 1 skipped`，前端 `24 files / 90 tests`，迁移升降升、固定 RAG、54 项脚本合同、构建与 smoke 均通过。
- Phase 8 smoke：通过；检查 14 项交付物、10 页 PPT、180 秒字幕、阶段 3–7 先决 smoke 和本地性能预算。
- Docker runtime：`DOCKER_RUNTIME_TESTED=False`（本机无 Docker CLI）。
- 远端 CI：`CI_RUNTIME_TESTED=False`（未推送，未执行）。
- 外部网络：`NETWORK_ACCESS_TESTED=False`。
- 真实模型规划：`REAL_MODEL_PLANNING_TESTED=False`。
- 真实设备路径：`REAL_DEVICE_PATHS_TESTED=False`。
