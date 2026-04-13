#!/usr/bin/env bash
# CloudGuard Pro CSPM v3 — Stop Script
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(basename "${SCRIPT_DIR}")" == "scripts" && echo "$(cd "${SCRIPT_DIR}/.." && pwd)" || echo "${SCRIPT_DIR}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; [[ "$(basename "${ROOT_DIR}")" == "scripts" ]] && ROOT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"

MODE=""
for arg in "$@"; do
  case "${arg}" in
    native|--native) MODE="native" ;;
    docker|--docker) MODE="docker" ;;
    *) echo "Usage: $0 [native|docker]"; exit 1 ;;
  esac
done
[[ -z "${MODE}" ]] && { echo "Usage: $0 [native|--native|docker|--docker]"; exit 1; }

GREEN='\033[0;32m'; NC='\033[0m'
success() { echo -e "${GREEN}✓${NC} $*"; }

PID_FILE="${ROOT_DIR}/cloudguard.pid"

case "${MODE}" in
  docker)
    cd "${ROOT_DIR}"
    if docker compose version &>/dev/null 2>&1; then docker compose down
    elif command -v docker-compose &>/dev/null; then docker-compose down
    else echo "Docker Compose not found."; exit 1; fi
    success "Docker containers stopped."
    ;;
  native)
    if [[ -f "${PID_FILE}" ]]; then
      PID=$(cat "${PID_FILE}")
      if kill -0 "${PID}" 2>/dev/null; then
        kill "${PID}" && success "Stopped CloudGuard Pro (PID ${PID})."
        rm -f "${PID_FILE}"
      else
        echo "Process ${PID} not running. Removing stale PID file."
        rm -f "${PID_FILE}"
      fi
    else
      # Fallback: kill by port
      PORT="${PORT:-8000}"
      PID=$(lsof -ti "tcp:${PORT}" 2>/dev/null || true)
      if [[ -n "${PID}" ]]; then
        kill "${PID}" && success "Stopped process on port ${PORT} (PID ${PID})."
      else
        echo "No CloudGuard Pro process found."
      fi
    fi
    ;;
esac
