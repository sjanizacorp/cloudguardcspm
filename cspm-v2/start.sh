#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "╔══════════════════════════════════════╗"
echo "║   CloudGuard CSPM v2 — Starting      ║"
echo "╚══════════════════════════════════════╝"
echo "→ Project root: $SCRIPT_DIR"

# ── Python version check ──────────────────────────────────────────────────────
PYTHON_BIN=""
CANDIDATES=(
  "/opt/homebrew/opt/python@3.12/bin/python3.12"
  "/opt/homebrew/opt/python@3.11/bin/python3.11"
  "/opt/homebrew/opt/python@3.13/bin/python3.13"
  "/opt/homebrew/opt/python@3.10/bin/python3.10"
  "/usr/local/opt/python@3.12/bin/python3.12"
  "/usr/local/opt/python@3.11/bin/python3.11"
  "/usr/local/bin/python3.12"
  "/usr/local/bin/python3.11"
  "python3.12" "python3.11" "python3.13" "python3.10" "python3"
)

if [ -n "$PYTHON_OVERRIDE" ]; then
  PYTHON_BIN="$PYTHON_OVERRIDE"
  echo "→ Using override: $PYTHON_BIN"
else
  for candidate in "${CANDIDATES[@]}"; do
    if command -v "$candidate" &>/dev/null 2>&1 || [ -x "$candidate" ]; then
      VERSION=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
      MAJOR=$(echo "$VERSION" | cut -d. -f1)
      MINOR=$(echo "$VERSION" | cut -d. -f2)
      if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -ge 10 ] && [ "$MINOR" -le 13 ]; then
        PYTHON_BIN="$candidate"
        echo "✓ Python $VERSION ($candidate)"
        break
      fi
    fi
  done
fi

if [ -z "$PYTHON_BIN" ]; then
  echo "❌ Python 3.10–3.13 not found. Install via: brew install python@3.12"
  exit 1
fi

if ! command -v node &>/dev/null; then
  echo "❌ Node.js not found. Install from: https://nodejs.org"
  exit 1
fi
echo "✓ Node $(node --version)"

# ── Backend ───────────────────────────────────────────────────────────────────
echo ""
echo "→ Setting up backend..."
cd "$SCRIPT_DIR/backend"

if [ -d "venv" ]; then
  EXISTING=$(venv/bin/python --version 2>/dev/null || echo "unknown")
  EXPECTED=$("$PYTHON_BIN" --version 2>/dev/null)
  if [ "$EXISTING" != "$EXPECTED" ]; then
    echo "  Recreating venv ($EXISTING → $EXPECTED)..."
    rm -rf venv
  fi
fi

"$PYTHON_BIN" -m venv venv
source venv/bin/activate
echo "  venv: $(python --version)"
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✓ Backend ready"

echo "→ Starting API on :8000..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# ── Frontend ──────────────────────────────────────────────────────────────────
cd "$SCRIPT_DIR/frontend"
echo ""
echo "→ Installing frontend dependencies..."
npm install -q
echo "✓ Frontend ready"
echo "→ Starting UI on :3000..."
npm run dev &
FRONTEND_PID=$!

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  CloudGuard CSPM v2 is running!                  ║"
echo "║                                                  ║"
echo "║  Dashboard  → http://localhost:3000              ║"
echo "║  API Docs   → http://localhost:8000/docs         ║"
echo "║                                                  ║"
echo "║  New in v2:                                      ║"
echo "║  • Persistent scan history                       ║"
echo "║  • Scheduled automatic scans                     ║"
echo "║  • Suppress / accept risk on findings            ║"
echo "║  • 50+ security checks (was 24)                  ║"
echo "║  • NIST 800-53 compliance framework              ║"
echo "║  • Score trend chart                             ║"
echo "║                                                  ║"
echo "║  Press Ctrl+C to stop                            ║"
echo "╚══════════════════════════════════════════════════╝"

trap "echo ''; echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
wait
