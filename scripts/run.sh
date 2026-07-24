#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

cd "${ROOT_DIR}"

case "${1:-}" in
  init-db)
    python scripts/init_db.py
    ;;
  api)
    uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
    ;;
  dashboard)
    streamlit run dashboard/app.py
    ;;
  agent)
    shift
    python agent/capture.py "$@"
    ;;
  *)
    echo "Usage: ./scripts/run.sh {init-db|api|dashboard|agent}"
    exit 1
    ;;
esac
