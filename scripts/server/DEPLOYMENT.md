# Model selector deployment

Server: jhk@121.48.164.89:1100. Deployed source: /home/user/jhk/project/ShieldChain.
Use SSH BindAddress 218.194.39.247 on this Windows computer while the present proxy routing is active. The address may change on another network.

The actual deployment tree differs from the local repository; modified files are staged in this directory and uploaded to the deployed tree only.

## State on 2026-09-02

- Frontend model selector, separate conversation histories, backend allowlist and file-based manager installed.
- Both directions of model switching and both models' real multi-turn chat verified. Qwen3.8 is left running for the user.
- Qwen3.8 on vLLM 0.17 passed real single-turn and multi-turn API tests (short reply about 0.9 seconds after warmup). Final config uses PP2/TP1, eager execution, default-precision KV cache, text-only/non-thinking mode. TP2 was not validated successfully.
- User explicitly approved Docker group access on 2026-09-02. Installed user service now uses `sg docker`; heartbeat reports can_switch=true and actual container recreation succeeded.
- Backend does NOT receive the Docker socket. A fixed-ID request file is consumed by the host manager. Shared/exclusive locks protect model-test inference during switching.
- Missing Docker access is reported to the page and disables switching without blocking chat with the active model.
- User service linger enabled. Shared control directory is scoped to data/model-control, uid10001/gid1010, mode2770.
- Switching now tests a real generation (up to 16 tokens, covering prefill and decode) before publishing ready, allowing up to 180 seconds for initial kernel warmup. Qwen test requests have a 120-second LLM deadline; all other adapter users retain the 30-second default. Qwen nginx route read timeout is 250 seconds.
- Both model configs use safetensors eager sequential loading, avoiding slow mmap random reads on the model-cache disk. This affects CPU memory while loading, not weight precision. Original local-llm config is backed up separately.
- Cache validation checks the active snapshot's index and referenced files. Historical .incomplete files are left untouched and do not invalidate complete snapshots.

## Deployment command

From /home/user/jhk/project/ShieldChain:

    docker compose -f compose.yaml -f compose.server.yaml -f compose.local-llm.yaml -f compose.model-control.yaml up -d --no-deps --pull never backend frontend

The model manager recreates local-llm only. It uses compose.qwen38.yaml for Qwen3.8, and the original local-llm overlay for Qwen3. Manual queue command: bash scripts/server/switch-model.sh qwen3|qwen38.

## Tests

8 model-control tests, 2 timeout regression tests and 3 frontend tests passed; TypeScript and production build passed. Browser confirmed Qwen3 chat. Both Qwen3 and Qwen3.8 passed the final smoke-model.py tests: real routing, multi-turn, inactive-model guard and allowlist. HTTP POST /select was verified against the deployed backend. Full round trip qwen3 → qwen38 → qwen3 → qwen38 completed.

## Recovery

Original affected source/config files: backups/model-selector-20260902/original.tgz, plus separate deepseek.py and compose.local-llm.yaml backups. Original images shieldchain-backend:local and shieldchain-frontend:local retained. Use original three compose files (without model-control) to restore original frontend/backend containers; inspect backup before restoring individual source files. Never delete model caches as part of rollback.

Temporary Docker download proxy PID379188 was verified and stopped after downloads/builds finished. Helper scripts remain under /home/user/jhk/tmp; no system proxy setting was changed. This helper is not required for inference.
