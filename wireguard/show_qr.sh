#!/usr/bin/env bash
set -euo pipefail

CONF_PATH="${1:-}"
if [[ -z "${CONF_PATH}" ]]; then
  echo "Usage: $0 path/to/client.conf" >&2
  exit 2
fi
if [[ ! -f "${CONF_PATH}" ]]; then
  echo "Config not found: ${CONF_PATH}" >&2
  exit 2
fi

if ! command -v qrencode >/dev/null 2>&1; then
  echo "qrencode not found. Install it first (Debian/Ubuntu): sudo apt install -y qrencode" >&2
  exit 1
fi

qrencode -t ansiutf8 < "${CONF_PATH}"


