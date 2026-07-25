#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${ROOT_DIR}/.run"
export PYTHONPATH="${ROOT_DIR}/src:${PYTHONPATH:-}"

API_PID="${RUN_DIR}/api.pid"
DASHBOARD_PID="${RUN_DIR}/dashboard.pid"
AGENT_PID="${RUN_DIR}/agent.pid"
API_LOG="${RUN_DIR}/api.log"
DASHBOARD_LOG="${RUN_DIR}/dashboard.log"
AGENT_LOG="${RUN_DIR}/agent.log"

PYTHON="${ROOT_DIR}/.venv/bin/python3"
if [[ ! -x "${PYTHON}" ]]; then
  PYTHON="$(command -v python3)"
fi

cd "${ROOT_DIR}"
mkdir -p "${RUN_DIR}"

is_running() {
  local pid_file="$1"
  [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" 2>/dev/null
}

start_process() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  shift 3

  if is_running "${pid_file}"; then
    echo "${name} already running (PID $(cat "${pid_file}"))"
    return 0
  fi

  echo "Starting ${name}..."
  nohup "$@" >> "${log_file}" 2>&1 &
  echo $! > "${pid_file}"
  echo "${name} started (PID $(cat "${pid_file}"), log: ${log_file})"
}

stop_process() {
  local name="$1"
  local pid_file="$2"

  if ! [[ -f "${pid_file}" ]]; then
    echo "${name} is not running."
    return 0
  fi

  local pid
  pid="$(cat "${pid_file}")"

  if kill -0 "${pid}" 2>/dev/null; then
    echo "Stopping ${name} (PID ${pid})..."
    kill "${pid}" 2>/dev/null || true
    sleep 1
    if kill -0 "${pid}" 2>/dev/null; then
      kill -9 "${pid}" 2>/dev/null || true
    fi
  else
    echo "${name} was not running (stale PID file)."
  fi

  rm -f "${pid_file}"
}

wait_for_api() {
  echo "Waiting for API to become ready..."
  for _ in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:8000/health" >/dev/null 2>&1; then
      echo "API is ready."
      return 0
    fi
    sleep 1
  done
  echo "API did not become ready in time. Check ${API_LOG}"
  return 1
}

cmd_start() {
  if [[ ! -f "${ROOT_DIR}/.env" ]]; then
    echo "Missing .env file. Copy .env.example to .env and configure it first."
    exit 1
  fi

  start_process "API" "${API_PID}" "${API_LOG}" \
    "${PYTHON}" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

  wait_for_api

  start_process "Dashboard" "${DASHBOARD_PID}" "${DASHBOARD_LOG}" \
    "${PYTHON}" -m streamlit run dashboard/app.py --server.port 8501 --server.headless true

  start_process "Agent" "${AGENT_PID}" "${AGENT_LOG}" \
    "${PYTHON}" agent/capture.py --daemon

  echo
  echo "All services started."
  echo "  Dashboard: http://localhost:8501"
  echo "  API:       http://127.0.0.1:8000"
  echo "  Logs:      ${RUN_DIR}/"
  echo
  echo "Stop everything with: ./scripts/run.sh stop"
}

cmd_stop() {
  stop_process "Agent" "${AGENT_PID}"
  stop_process "Dashboard" "${DASHBOARD_PID}"
  stop_process "API" "${API_PID}"
  echo "All services stopped."
}

cmd_status() {
  local running=0

  for entry in "API:${API_PID}" "Dashboard:${DASHBOARD_PID}" "Agent:${AGENT_PID}"; do
    local name="${entry%%:*}"
    local pid_file="${entry##*:}"
    if is_running "${pid_file}"; then
      echo "${name}: running (PID $(cat "${pid_file}"))"
      running=$((running + 1))
    else
      echo "${name}: stopped"
      rm -f "${pid_file}"
    fi
  done

  if [[ "${running}" -gt 0 ]]; then
    echo
    echo "Dashboard: http://localhost:8501"
    echo "API:       http://127.0.0.1:8000"
  fi
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

case "${1:-start}" in
  start)
    cmd_start
    ;;
  stop)
    cmd_stop
    ;;
  status)
    cmd_status
    ;;
  restart)
    cmd_restart
    ;;
  init-db)
    "${PYTHON}" scripts/init_db.py
    ;;
  logs)
    tail -f "${API_LOG}" "${DASHBOARD_LOG}" "${AGENT_LOG}"
    ;;
  *)
    cat <<EOF
Usage: ./scripts/run.sh [command]

Commands:
  start     Start API, dashboard, and agent (default)
  stop      Stop all services
  status    Show service status
  restart   Restart all services
  init-db   Initialize database tables and admin user
  logs      Tail all service logs

Examples:
  ./scripts/run.sh
  ./scripts/run.sh start
  ./scripts/run.sh stop
  ./scripts/run.sh status
EOF
    exit 1
    ;;
esac
