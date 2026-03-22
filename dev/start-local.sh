#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_HOST="${MOCK_HOST:-127.0.0.1}"
MOCK_PORT="${MOCK_PORT:-8765}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-8088}"

MOCK_PID=""
PHP_PID=""

cleanup() {
    local exit_code=$?

    if [[ -n "${PHP_PID}" ]] && kill -0 "${PHP_PID}" 2>/dev/null; then
        kill "${PHP_PID}" 2>/dev/null || true
        wait "${PHP_PID}" 2>/dev/null || true
    fi

    if [[ -n "${MOCK_PID}" ]] && kill -0 "${MOCK_PID}" 2>/dev/null; then
        kill "${MOCK_PID}" 2>/dev/null || true
        wait "${MOCK_PID}" 2>/dev/null || true
    fi

    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

cd "${ROOT_DIR}"

python3 tools/mock_viewer_api.py --host "${MOCK_HOST}" --port "${MOCK_PORT}" &
MOCK_PID=$!

VIEWER_API_BASE="http://${MOCK_HOST}:${MOCK_PORT}" \
VIEWER_DISABLE_AUTH=1 \
php -S "${FRONTEND_HOST}:${FRONTEND_PORT}" -t public &
PHP_PID=$!

echo "Local mock stack started"
echo "Mock API: http://${MOCK_HOST}:${MOCK_PORT}"
echo "Frontend: http://${FRONTEND_HOST}:${FRONTEND_PORT}/webhookviewer.php"
echo "Press Ctrl+C to stop both servers"

wait "${MOCK_PID}" "${PHP_PID}"
