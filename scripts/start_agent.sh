#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${ROOT_DIR}/.run"
PID_FILE="${RUN_DIR}/agent.pid"
LOG_FILE="${RUN_DIR}/agent.log"

export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"
cd "${ROOT_DIR}"

mkdir -p "${RUN_DIR}"

if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
  echo "Agent already running with PID $(cat "${PID_FILE}")"
  exit 1
fi

echo "Starting traffic capture agent in background..."
nohup "${ROOT_DIR}/.venv/bin/python3" agent/capture.py --daemon "$@" >> "${LOG_FILE}" 2>&1 &
echo $! > "${PID_FILE}"

echo "Agent started (PID $(cat "${PID_FILE}"))"
echo "Logs: ${LOG_FILE}"
