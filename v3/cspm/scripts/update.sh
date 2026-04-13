#!/usr/bin/env bash
###############################################################################
# CloudGuard Pro CSPM v3 — Update / Clean Script
# Aniza Corp | Shahryar Jahangir
#
# Run this BEFORE starting after extracting a new package.
# Clears old Vite/React build artifacts that override the self-contained UI.
###############################################################################
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo -e "${BOLD}▶ CloudGuard Pro v3 — Clearing stale build artifacts...${NC}"
echo ""

DIST="${ROOT_DIR}/frontend/dist"

# Remove the Vite assets directory (fingerprinted JS/CSS bundles)
if [[ -d "${DIST}/assets" ]]; then
  warn "Removing stale Vite assets: ${DIST}/assets/"
  rm -rf "${DIST}/assets"
  success "Removed frontend/dist/assets/"
else
  info "No stale assets directory found."
fi

# Remove any fingerprinted JS/CSS at root of dist
for pattern in "*.js" "*.css" "shield.svg" "vite.svg" "*.ico"; do
  for f in "${DIST}"/${pattern}; do
    if [[ -f "${f}" ]]; then
      warn "Removing stale file: $(basename ${f})"
      rm -f "${f}"
    fi
  done
done

# Verify our self-contained index.html is present
if [[ -f "${DIST}/index.html" ]]; then
  if grep -q "self-contained-no-vite" "${DIST}/index.html" 2>/dev/null; then
    success "✓ frontend/dist/index.html is the correct self-contained build"
  else
    warn "frontend/dist/index.html exists but may be the OLD Vite/React version."
    warn "Re-extract the CloudGuard package to get the correct index.html."
    warn "  tar -xzf cloudguard-pro-cspm-v3.0.0.tar.gz"
  fi
else
  warn "frontend/dist/index.html not found — re-extract the package."
fi

echo ""
success "Done. Now restart: ./scripts/stop.sh native && ./scripts/start.sh native"
