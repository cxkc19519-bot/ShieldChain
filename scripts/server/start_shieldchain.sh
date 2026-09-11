#!/usr/bin/env bash
set -Eeuo pipefail

# ShieldChain school-server helper. It is intentionally scoped to jhk's home.
EXPECTED_USER="${SHIELDCHAIN_SERVER_USER:-jhk}"
PROJECT_ROOT="${SHIELDCHAIN_SERVER_ROOT:-/home/user/jhk/project/ShieldChain}"
ACTION="${1:-start}"

die() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

info() {
  printf '\n==> %s\n' "$*"
}

if [[ "$(id -un)" != "$EXPECTED_USER" ]]; then
  die "请使用获授权的 ${EXPECTED_USER} 账号运行；当前账号为 $(id -un)。"
fi

[[ "$PROJECT_ROOT" == /home/user/jhk/* ]] || die "项目目录必须位于 /home/user/jhk 内。"
[[ -d "$PROJECT_ROOT" ]] || die "项目目录不存在：$PROJECT_ROOT"
[[ -f "$PROJECT_ROOT/compose.yaml" ]] || die "缺少 compose.yaml。"
[[ -f "$PROJECT_ROOT/compose.server.yaml" ]] || die "缺少 compose.server.yaml。"
[[ -f "$PROJECT_ROOT/.env" ]] || die "缺少服务器私有配置：$PROJECT_ROOT/.env"
grep -q '^DEEPSEEK_API_KEY=.' "$PROJECT_ROOT/.env" || die ".env 中未配置 DEEPSEEK_API_KEY。"

command -v docker >/dev/null 2>&1 || die "未安装 Docker。"
docker info >/dev/null 2>&1 || die "Docker 未运行，或当前账号没有 Docker 权限。"
docker compose version >/dev/null 2>&1 || die "缺少 Docker Compose 插件。"

cd "$PROJECT_ROOT"

COMPOSE=(
  docker compose
  -f compose.yaml
  -f compose.server.yaml
)

show_status() {
  "${COMPOSE[@]}" ps
  printf '\n前端健康：'
  curl -fsS --max-time 5 http://127.0.0.1:8080/healthz 2>/dev/null || printf '不可用'
  printf '\n后端就绪：'
  curl -fsS --max-time 5 http://127.0.0.1:8080/api/v1/health/ready 2>/dev/null || printf '不可用'
  printf '\n'
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local attempts="$3"
  local delay="$4"
  local count
  for ((count = 1; count <= attempts; count++)); do
    if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
      printf '%s 已就绪。\n' "$name"
      return 0
    fi
    printf '\r等待 %s：%d/%d' "$name" "$count" "$attempts"
    sleep "$delay"
  done
  printf '\n'
  return 1
}

case "$ACTION" in
  start)
    info "使用 DeepSeek API 启动数据库迁移、ShieldChain 后端和前端"
    "${COMPOSE[@]}" up -d --no-build
    info "等待服务健康"
    wait_for_url "ShieldChain 前端" "http://127.0.0.1:8080/healthz" 40 5 \
      || die "前端未就绪，请运行：$0 logs"
    wait_for_url "ShieldChain 后端" "http://127.0.0.1:8080/api/v1/health/ready" 40 5 \
      || die "后端未就绪，请运行：$0 logs"
    info "启动完成"
    show_status
    printf '\n请保持本机 SSH 隧道，并访问 http://127.0.0.1:8080\n'
    ;;
  stop)
    info "停止 ShieldChain（保留数据卷和持久化文件）"
    "${COMPOSE[@]}" down --remove-orphans
    ;;
  restart)
    info "重启 ShieldChain（不删除数据）"
    "${COMPOSE[@]}" restart
    wait_for_url "ShieldChain 前端" "http://127.0.0.1:8080/healthz" 40 5 \
      || die "重启后前端未就绪，请运行：$0 logs"
    show_status
    ;;
  status)
    show_status
    ;;
  logs)
    "${COMPOSE[@]}" logs --tail 160 backend frontend migrate
    ;;
  *)
    cat >&2 <<'USAGE'
用法：./scripts/server/start_shieldchain.sh [start|stop|restart|status|logs]

  start    启动完整服务器环境（默认）
  stop     停止服务，但保留数据
  restart  重启现有服务
  status   查看容器和健康状态
  logs     查看最近日志
USAGE
    exit 2
    ;;
esac
