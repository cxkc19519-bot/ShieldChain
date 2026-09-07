# Phase 8 离线性能与交付基线

> 文档状态：历史验收快照。记录当时版本的测试结果与限制，不等同于当前版本状态。

## 运行信息

- 日期：2026-07-24
- Profile：`offline-local`
- Python：CPython 3.14.6
- 平台：Windows `win32` / AMD64
- 预算文件：`tests/fixtures/quality/phase8_baseline_v1.json`
- 命令：`powershell -ExecutionPolicy Bypass -File tests\scripts\run-phase8-baseline.ps1`

## 固定场景结果

| 场景 | 预热 | 样本 | 单位 | p50 | p95 | 最大 p95 | 结果 |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |
| `health_live_http` | 3 | 25 | ms | 1.656 | 2.499 | 100.000 | 通过 |
| `rag_dataset_load` | 3 | 25 | ms | 0.099 | 0.114 | 100.000 | 通过 |

阈值刻意宽于本机稳定观测，用于发现数量级回归而非宣称生产容量。报告记录 p50、p95、样本量、单位和隐私安全的运行时元数据，不记录主机名、用户名、仓库路径、tenant、凭据或请求内容。

## 交付物基线

`delivery/manifest.json` 已建立源代码、设计、开发说明、测试报告、总结、PPT 和视频的机器可读清单。当前代码与文档标记为 `available`，未完成的 PPT、视频、最终 ZIP 和校验和保持 `planned` 且不在仓库中；合同禁止绝对路径和父目录逃逸。

## 验证边界

- `NETWORK_ACCESS_TESTED=False`
- `REAL_MODEL_PLANNING_TESTED=False`
- `REAL_DEVICE_PATHS_TESTED=False`

当前结果只覆盖本机进程内 HTTP liveness 与固定双语 RAG 数据集加载，不代表生产并发、网络、云模型、安全设备或容器性能。后续 Task 3 将加入数据库、RAG 检索和报告聚合的固定容量场景。
