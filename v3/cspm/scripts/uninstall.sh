#!/usr/bin/env bash
###############################################################################
# CloudGuard Pro CSPM v3 — Uninstall Script
# Usage: ./scripts/uninstall.sh [native|docker]
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "${SCRIPT_DIR}")" == "scripts" ]]; then
  ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
  ROOT_DIR="${SCRIPT_DIR}"
fi

MODE=""
for arg in "$@"; do
  case "${arg}" in
    native|--native) MODE="native" ;;
    docker|--docker) MODE="docker" ;;
    *) echo "Usage: $0 [native|docker]"; exit 1 ;;
  esac
done

[[ -z "${MODE}" ]] && { echo "Usage: $0 [native|--native|docker|--docker]"; exit 1; }

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
echo -e "${RED}⚠  This will remove CloudGuard Pro v3 data for mode: ${MODE}${NC}"
read -r -p "Type 'yes' to confirm: " CONFIRM
[[ "${CONFIRM}" != "yes" ]] && echo "Cancelled." && exit 0

case "${MODE}" in
  docker)
    cd "${ROOT_DIR}"
    if docker compose version &>/dev/null 2>&1; then
      docker compose down -v --remove-orphans 2>/dev/null || true
    elif command -v docker-compose &>/dev/null; then
      docker-compose down -v --remove-orphans 2>/dev/null || true
    fi
    docker rmi cloudguard-pro-cspm:latest 2>/dev/null || true
    echo -e "${GREEN}✓${NC} Docker containers, volumes, and image removed."
    ;;
  native)
    echo -e "${YELLOW}Removing venv, database, built frontend, and .env...${NC}"
    rm -rf "${ROOT_DIR}/venv"
    rm -f  "${ROOT_DIR}/cspm.db"
    rm -rf "${ROOT_DIR}/frontend/dist"
    rm -rf "${ROOT_DIR}/frontend/node_modules"
    rm -f  "${ROOT_DIR}/.env"
    echo -e "${GREEN}✓${NC} Native installation removed."
    ;;
esac
echo -e "${GREEN}✓${NC} Uninstall complete."
