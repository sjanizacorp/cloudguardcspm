###############################################################################
# CloudGuard Pro CSPM — Dockerfile
# Aniza Corp | Shahryar Jahangir
# Multi-stage: frontend build → backend runtime
###############################################################################

# ── Stage 1: Build React frontend ─────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json ./
RUN npm install --silent
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python backend runtime ───────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="Shahryar Jahangir <shahryar@anizacorp.com>"
LABEL description="CloudGuard Pro CSPM v3 — Multi-cloud Security Posture Management"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cspm && useradd -r -g cspm -d /app -s /sbin/nologin cspm

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ ./backend/
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Writable dirs
RUN mkdir -p /tmp/cspm_reports && chown -R cspm:cspm /app /tmp/cspm_reports

USER cspm

ENV HOST=0.0.0.0
ENV PORT=8000
ENV DATABASE_URL=sqlite:///./cspm.db
ENV SEED_DEMO_DATA=true
ENV REPORTS_DIR=/tmp/cspm_reports
ENV PYTHONPATH=/app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
