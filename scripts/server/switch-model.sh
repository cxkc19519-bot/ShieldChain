#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in qwen3|qwen38) ;; *) echo "Usage: $0 qwen3|qwen38" >&2; exit 2 ;; esac
export QWEN_CONTROL_ROOT=/home/user/jhk/project/ShieldChain/data/model-control
export PYTHONPATH=/home/user/jhk/project/ShieldChain/backend/src
python3 -c 'import sys; from shieldchain.qwen_experience.model_control import select; print(select(sys.argv[1]))' "$1"
