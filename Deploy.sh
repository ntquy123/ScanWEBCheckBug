#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
BRANCH="${BRANCH:-}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

log() {
  printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  printf '\n[ERROR] %s\n' "$*" >&2
  exit 1
}

run() {
  log "$*"
  "$@"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command_exists docker-compose; then
    docker-compose "$@"
  else
    fail "Docker Compose chua duoc cai. Cai Docker Compose plugin hoac docker-compose truoc."
  fi
}

log "Deploy ScanWEBCheckBug"
cd "$PROJECT_DIR"

command_exists git || fail "git chua duoc cai tren server."
command_exists docker || fail "docker chua duoc cai tren server."

if [ ! -f "$COMPOSE_FILE" ]; then
  fail "Khong tim thay $COMPOSE_FILE trong $PROJECT_DIR"
fi

if [ ! -d ".git" ]; then
  fail "$PROJECT_DIR khong phai git repository. Hay clone source code len server truoc."
fi

if [ -n "$(git status --porcelain)" ]; then
  fail "Working tree dang co thay doi local. Commit/stash truoc khi deploy de tranh mat code."
fi

run git fetch --all --prune

if [ -n "$BRANCH" ]; then
  run git checkout "$BRANCH"
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" = "HEAD" ]; then
  fail "Repo dang o detached HEAD. Hay checkout branch can deploy hoac chay BRANCH=<branch> ./Deploy.sh"
fi

run git pull --ff-only origin "$CURRENT_BRANCH"

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  log "Chua co .env, tao tu .env.example"
  cp .env.example .env
fi

run compose -f "$COMPOSE_FILE" pull --ignore-pull-failures
run compose -f "$COMPOSE_FILE" up --build -d
run compose -f "$COMPOSE_FILE" ps

log "Kiem tra API health"
if command_exists curl; then
  curl --fail --silent --show-error http://localhost:4000/api/health || true
  printf '\n'
else
  log "curl chua duoc cai, bo qua health check."
fi

log "Deploy xong"
printf 'Web: http://<SERVER_IP>:5173\n'
printf 'API: http://<SERVER_IP>:4000/api/health\n'
printf 'Logs: docker compose logs -f api worker web\n'
