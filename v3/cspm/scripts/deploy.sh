#!/usr/bin/env bash
###############################################################################
# CloudGuard Pro CSPM v3 — Deploy Script
# Aniza Corp | Shahryar Jahangir
#
# Usage:
#   ./deploy.sh native          ./deploy.sh --native
#   ./deploy.sh docker          ./deploy.sh --docker
#   ./deploy.sh native --no-demo
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "${SCRIPT_DIR}")" == "scripts" ]]; then
  ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
  ROOT_DIR="${SCRIPT_DIR}"
fi

VERSION="3.0.0"
MODE=""
SEED_DEMO="true"

for arg in "$@"; do
  case "${arg}" in
    native|--native)   MODE="native" ;;
    docker|--docker)   MODE="docker" ;;
    --no-demo|no-demo) SEED_DEMO="false" ;;
    --help|-h) echo "Usage: $0 [native|--native|docker|--docker] [--no-demo]"; exit 0 ;;
    *) echo "Unknown argument: ${arg}"; echo "Usage: $0 [native|--native|docker|--docker] [--no-demo]"; exit 1 ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║   CloudGuard Pro CSPM v${VERSION} — Deploy          ║"
echo "║   Aniza Corp | Shahryar Jahangir                 ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

[[ -z "${MODE}" ]] && {
  echo -e "${RED}Error: No deployment mode specified.${NC}"
  echo "Usage: $0 [native|--native|docker|--docker] [--no-demo]"
  exit 1
}

# ── Python version check ──────────────────────────────────────────────────────
check_python() {
  local bin="${1}"
  local maj min
  maj=$("${bin}" -c 'import sys; print(sys.version_info.major)')
  min=$("${bin}" -c 'import sys; print(sys.version_info.minor)')

  if [[ "${maj}" -lt 3 ]] || [[ "${maj}" -eq 3 && "${min}" -lt 9 ]]; then
    error "Python 3.9+ required — found ${maj}.${min}. Install from https://python.org"
  fi

  info "Python: ${maj}.${min}"

  # Python 3.14+ — set the official PyO3 ABI3 compatibility flag so that
  # pydantic-core (which uses pyo3 internally) can compile.
  # We also ensure pydantic-core>=2.27.0 is in requirements.txt (which it is).
  if [[ "${maj}" -eq 3 && "${min}" -ge 14 ]]; then
    warn "Python 3.14 detected."
    warn "Setting PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 (required for pydantic-core on 3.14)."
    export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
  fi
}

# ── Stale venv detection ──────────────────────────────────────────────────────
# If a venv exists but was built with a different Python version, or has the
# old pydantic-core pinned, blow it away so pip resolves fresh.
maybe_clean_venv() {
  local venv="${ROOT_DIR}/venv"
  if [[ ! -d "${venv}" ]]; then
    return 0
  fi

  # Check if venv Python matches current Python
  local venv_py="${venv}/bin/python"
  if [[ ! -f "${venv_py}" ]]; then
    return 0
  fi

  local sys_maj sys_min venv_maj venv_min
  sys_maj=$(python3 -c 'import sys; print(sys.version_info.major)')
  sys_min=$(python3 -c 'import sys; print(sys.version_info.minor)')
  venv_maj=$("${venv_py}" -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
  venv_min=$("${venv_py}" -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")

  if [[ "${sys_maj}.${sys_min}" != "${venv_maj}.${venv_min}" ]]; then
    warn "Existing venv was built with Python ${venv_maj}.${venv_min} but current Python is ${sys_maj}.${sys_min}."
    warn "Removing stale venv to force clean install..."
    rm -rf "${venv}"
    success "Stale venv removed."
    return 0
  fi

  # Check if old pydantic-core (<2.27) is installed — if so, force reinstall
  local installed_pdcore
  installed_pdcore=$("${venv_py}" -c "
import importlib.metadata, sys
try:
    v = importlib.metadata.version('pydantic-core')
    parts = v.split('.')
    major, minor = int(parts[0]), int(parts[1])
    if major < 2 or (major == 2 and minor < 27):
        print('old')
    else:
        print('ok')
except Exception:
    print('missing')
" 2>/dev/null || echo "missing")

  if [[ "${installed_pdcore}" == "old" ]]; then
    warn "Installed pydantic-core is older than 2.27.0 (incompatible with Python 3.14)."
    warn "Removing venv to force fresh install with pydantic-core>=2.27.0..."
    rm -rf "${venv}"
    success "Old venv removed."
  elif [[ "${installed_pdcore}" == "ok" ]]; then
    info "Existing venv has compatible pydantic-core — reusing."
  fi
}

# ── Write/update .env ─────────────────────────────────────────────────────────
setup_env() {
  if [[ ! -f "${ROOT_DIR}/.env" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    success "Created .env from .env.example"
    info "Review ${ROOT_DIR}/.env and set cloud credentials before scanning."
  fi
  if grep -q "^SEED_DEMO_DATA=" "${ROOT_DIR}/.env" 2>/dev/null; then
    sed -i.bak "s/^SEED_DEMO_DATA=.*/SEED_DEMO_DATA=${SEED_DEMO}/" "${ROOT_DIR}/.env"
    rm -f "${ROOT_DIR}/.env.bak"
  else
    echo "SEED_DEMO_DATA=${SEED_DEMO}" >> "${ROOT_DIR}/.env"
  fi
}

# ─── NATIVE ───────────────────────────────────────────────────────────────────
deploy_native() {
  info "Mode: native | Demo data: ${SEED_DEMO} | Root: ${ROOT_DIR}"

  command -v python3 &>/dev/null || error "python3 not found. Install from https://python.org"
  check_python "python3"
  maybe_clean_venv

  # Create venv if it doesn't exist
  if [[ ! -d "${ROOT_DIR}/venv" ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv "${ROOT_DIR}/venv"
    success "Virtual environment created."
  fi

  local PIP="${ROOT_DIR}/venv/bin/pip"
  local PYTHON="${ROOT_DIR}/venv/bin/python"

  # Run the version check on the venv python too (exports PYO3_USE_ABI3_FORWARD_COMPATIBILITY if needed)
  check_python "${PYTHON}"

  info "Upgrading pip..."
  "${PIP}" install --quiet --upgrade pip

  info "Installing Python dependencies..."
  info "  Key package: pydantic-core>=2.27.0 (required for Python 3.14 compatibility)"

  # PYO3_USE_ABI3_FORWARD_COMPATIBILITY is already exported by check_python() if Python 3.14+
  # Passing it explicitly here as well to be certain it's visible to pip's subprocess
  if [[ "${PYO3_USE_ABI3_FORWARD_COMPATIBILITY:-}" == "1" ]]; then
    info "  PyO3 ABI3 forward-compatibility: ENABLED"
    PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 "${PIP}" install -r "${ROOT_DIR}/requirements.txt"
  else
    "${PIP}" install -r "${ROOT_DIR}/requirements.txt"
  fi

  success "Python dependencies installed."

  # Verify pydantic-core version after install
  local installed_ver
  installed_ver=$("${PYTHON}" -c "import importlib.metadata; print(importlib.metadata.version('pydantic-core'))" 2>/dev/null || echo "unknown")
  info "pydantic-core installed: ${installed_ver}"

  # ── Frontend ──────────────────────────────────────────────────────────────
  # CloudGuard uses a self-contained single-file frontend (frontend/dist/index.html).
  # It requires NO build step — Node.js is NOT needed.
  # The old Vite/React build artifacts are cleared to prevent them overriding the
  # self-contained index.html.
  info "Clearing any stale Vite build artifacts..."
  rm -rf "${ROOT_DIR}/frontend/dist/assets"
  rm -f "${ROOT_DIR}/frontend/dist"/*.js \
        "${ROOT_DIR}/frontend/dist"/*.css \
        "${ROOT_DIR}/frontend/dist"/*.svg \
        "${ROOT_DIR}/frontend/dist/shield.svg" 2>/dev/null || true
  if [[ -f "${ROOT_DIR}/frontend/dist/index.html" ]]; then
    success "Frontend ready: frontend/dist/index.html (self-contained, no build needed)"
  else
    warn "frontend/dist/index.html missing — re-extract the package."
  fi

  setup_env

  echo ""
  success "Native deployment complete."
  echo -e "  ${BOLD}Start:${NC}     ./scripts/start.sh native"
  echo -e "  ${BOLD}Dashboard:${NC} http://localhost:${PORT:-8000}"
  echo ""
}

# ─── DOCKER ───────────────────────────────────────────────────────────────────
deploy_docker() {
  info "Mode: docker | Demo data: ${SEED_DEMO} | Root: ${ROOT_DIR}"
  info "Docker uses Python 3.11 in the image — no Python 3.14 issues."

  command -v docker &>/dev/null || error "Docker not installed. See https://docs.docker.com/get-docker/"

  if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
  else
    error "Docker Compose not found. Update Docker Desktop or install the compose plugin."
  fi
  info "Using: ${COMPOSE_CMD}"

  cd "${ROOT_DIR}"
  setup_env

  info "Building Docker image (may take 2-5 min first time)..."
  ${COMPOSE_CMD} build
  success "Docker image built."

  echo ""
  success "Docker deployment ready."
  echo -e "  ${BOLD}Start:${NC}     ./scripts/start.sh docker"
  echo -e "  ${BOLD}Dashboard:${NC} http://localhost:${PORT:-8000}"
  echo ""
}

case "${MODE}" in
  native) deploy_native ;;
  docker) deploy_docker ;;
esac
