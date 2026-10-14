#!/usr/bin/env bash
# One command: build the frontend and run everything on http://localhost:8000
set -e
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a
(cd frontend && npm install --no-audit --no-fund && npm run build)
python3 -m venv .venv 2>/dev/null || true
. .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"
