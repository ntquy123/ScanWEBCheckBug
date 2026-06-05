#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
BRANCH_INPUT="${BRANCH-}"
PULL_IMAGES_INPUT="${PULL_IMAGES-}"
API_PORT_INPUT="${API_PORT-}"
WEB_PORT_INPUT="${WEB_PORT-}"
BRANCH="$BRANCH_INPUT"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
PULL_IMAGES="false"
API_PORT="4000"
WEB_PORT="5173"

export DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}"
export COMPOSE_DOCKER_CLI_BUILD="${COMPOSE_DOCKER_CLI_BUILD:-1}"

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

if [ -f ".env" ]; then
  set -a
  . ./.env
  set +a
fi

BRANCH="${BRANCH_INPUT:-${BRANCH:-}}"
PULL_IMAGES="${PULL_IMAGES_INPUT:-${PULL_IMAGES:-false}}"
API_PORT="${API_PORT_INPUT:-${API_PORT:-4000}}"
WEB_PORT="${WEB_PORT_INPUT:-${WEB_PORT:-5173}}"

if [ "$PULL_IMAGES" = "true" ]; then
  run compose -f "$COMPOSE_FILE" pull --ignore-pull-failures
else
  log "Bo qua docker compose pull. Dat PULL_IMAGES=true ./Deploy.sh neu muon pull image moi."
fi

run compose -f "$COMPOSE_FILE" up --build -d
run compose -f "$COMPOSE_FILE" ps

log "Kiem tra API health"
if command_exists curl; then
  curl --fail --silent --show-error "http://localhost:${API_PORT}/api/health" || true
  printf '\n'
else
  log "curl chua duoc cai, bo qua health check."
fi

log "Deploy xong"
printf 'Web: http://<SERVER_IP>:%s\n' "$WEB_PORT"
printf 'API: http://<SERVER_IP>:%s/api/health\n' "$API_PORT"
printf 'Logs: docker compose logs -f api worker web\n'
