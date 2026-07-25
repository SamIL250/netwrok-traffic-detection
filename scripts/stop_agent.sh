#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${ROOT_DIR}/.run/agent.pid"

if [[ ! -f "${PID_FILE}" ]]; then
  echo "Agent is not running (no PID file)."
  exit 1
fi

PID="$(cat "${PID_FILE}")"

if ! kill -0 "${PID}" 2>/dev/null; then
  echo "Stale PID file found. Removing ${PID_FILE}"
  rm -f "${PID_FILE}"
  exit 1
fi

echo "Stopping agent (PID ${PID})..."
kill "${PID}"
rm -f "${PID_FILE}"
echo "Agent stopped."
