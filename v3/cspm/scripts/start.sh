#!/usr/bin/env bash
###############################################################################
# CloudGuard Pro CSPM v3 — Start Script (background mode)
# Aniza Corp | Shahryar Jahangir
#
# Usage:
#   ./scripts/start.sh native     (or --native)
#   ./scripts/start.sh docker     (or --docker)
#   ./scripts/start.sh native --foreground   (attach to terminal)
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "${SCRIPT_DIR}")" == "scripts" ]]; then
  ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
  ROOT_DIR="${SCRIPT_DIR}"
fi

MODE=""
FOREGROUND=false
for arg in "$@"; do
  case "${arg}" in
    native|--native)       MODE="native" ;;
    docker|--docker)       MODE="docker" ;;
    --foreground|-f)       FOREGROUND=true ;;
    --help|-h) echo "Usage: $0 [native|docker] [--foreground]"; exit 0 ;;
    *) echo "Unknown argument: ${arg}"; exit 1 ;;
  esac
done
[[ -z "${MODE}" ]] && { echo "Usage: $0 [native|--native|docker|--docker] [--foreground]"; exit 1; }

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }

PID_FILE="${ROOT_DIR}/cloudguard.pid"
LOG_FILE="${ROOT_DIR}/logs/cloudguard.log"
mkdir -p "${ROOT_DIR}/logs"

load_env() {
  [[ -f "${ROOT_DIR}/.env" ]] && { set -a; source "${ROOT_DIR}/.env"; set +a; }
}

case "${MODE}" in
  native)
    load_env
    if [[ ! -f "${ROOT_DIR}/venv/bin/uvicorn" ]]; then
      echo "Virtual environment not found. Run: ./scripts/deploy.sh native"; exit 1
    fi
    # Check if already running
    if [[ -f "${PID_FILE}" ]]; then
      OLD_PID=$(cat "${PID_FILE}")
      if kill -0 "${OLD_PID}" 2>/dev/null; then
        warn "CloudGuard Pro is already running (PID ${OLD_PID})."
        warn "Dashboard: http://localhost:${PORT:-8000}"
        warn "To stop:  ./scripts/stop.sh native"
        exit 0
      else
        rm -f "${PID_FILE}"
      fi
    fi

    # Auto-clear stale Vite build artifacts that would override our self-contained UI
    if [[ -d "${ROOT_DIR}/frontend/dist/assets" ]]; then
      echo "[WARN]  Removing stale Vite build artifacts from frontend/dist/assets/"
      rm -rf "${ROOT_DIR}/frontend/dist/assets"
    fi
    for _f in "${ROOT_DIR}/frontend/dist"/*.js               "${ROOT_DIR}/frontend/dist"/*.css               "${ROOT_DIR}/frontend/dist/shield.svg"; do
      [[ -f "${_f}" ]] && rm -f "${_f}" 2>/dev/null && echo "[WARN]  Removed stale: $(basename "${_f}")"
    done

    export PYTHONPATH="${ROOT_DIR}"
    HOST="${HOST:-0.0.0.0}"
    PORT="${PORT:-8000}"

    echo -e "${BOLD}▶ CloudGuard Pro v3 — starting (native, background)...${NC}"
    info "Dashboard: http://localhost:${PORT}"
    info "API docs:  http://localhost:${PORT}/docs"
    info "Log file:  ${LOG_FILE}"

    if [[ "${FOREGROUND}" == "true" ]]; then
      info "Running in foreground (Ctrl+C to stop)"
      exec "${ROOT_DIR}/venv/bin/uvicorn" backend.main:app \
        --host "${HOST}" --port "${PORT}" \
        --workers "${WORKERS:-1}" \
        --log-level "${LOG_LEVEL:-info}"
    else
      # Start in background, redirect to rotating log
      nohup "${ROOT_DIR}/venv/bin/uvicorn" backend.main:app \
        --host "${HOST}" --port "${PORT}" \
        --workers "${WORKERS:-1}" \
        --log-level "${LOG_LEVEL:-info}" \
        >> "${LOG_FILE}" 2>&1 &
      echo $! > "${PID_FILE}"
      sleep 1
      # Verify it started
      if kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        success "CloudGuard Pro started (PID $(cat "${PID_FILE}"))"
        echo ""
        echo -e "  Dashboard:  http://localhost:${PORT}"
        echo -e "  API docs:   http://localhost:${PORT}/docs"
        echo -e "  Log file:   ${LOG_FILE}"
        echo -e "  PID file:   ${PID_FILE}"
        echo ""
        echo -e "  Stop:       ./scripts/stop.sh native"
        echo -e "  Follow log: tail -f ${LOG_FILE}"
      else
        echo "Failed to start. Check: ${LOG_FILE}"
        cat "${LOG_FILE}" | tail -20
        rm -f "${PID_FILE}"
        exit 1
      fi
    fi
    ;;

  docker)
    load_env
    cd "${ROOT_DIR}"
    if docker compose version &>/dev/null 2>&1; then
      COMPOSE_CMD="docker compose"
    elif command -v docker-compose &>/dev/null; then
      COMPOSE_CMD="docker-compose"
    else
      echo "Docker Compose not found."; exit 1
    fi
    echo -e "${BOLD}▶ CloudGuard Pro v3 — starting (docker)...${NC}"
    ${COMPOSE_CMD} up -d
    success "Container started."
    echo ""
    echo -e "  Dashboard: http://localhost:${PORT:-8000}"
    echo -e "  API docs:  http://localhost:${PORT:-8000}/docs"
    echo -e "  Logs:      docker compose logs -f"
    echo -e "  Stop:      ./scripts/stop.sh docker"
    ;;
esac
