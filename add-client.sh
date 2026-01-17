#!/usr/bin/env bash
set -euo pipefail

# Adds a new WireGuard client to /etc/wireguard/wg0.conf and writes a client .conf.
#
# Usage:
#   sudo bash add-client.sh <client-name>

CLIENT_NAME="${1:-}"
if [[ -z "${CLIENT_NAME}" ]]; then
  echo "Usage: $0 <client-name>" >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

WG_IFACE="${WG_IFACE:-wg0}"
PARAMS_FILE="/etc/wireguard/${WG_IFACE}.params"
if [[ ! -f "${PARAMS_FILE}" ]]; then
  echo "Missing ${PARAMS_FILE}. Run install.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${PARAMS_FILE}"

CONF_FILE="/etc/wireguard/${WG_IFACE}.conf"
if [[ ! -f "${CONF_FILE}" ]]; then
  echo "Missing ${CONF_FILE}. Run install.sh first." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENTS_DIR="${SCRIPT_DIR}/clients"
mkdir -p "${CLIENTS_DIR}"

OUT_CONF="${CLIENTS_DIR}/${CLIENT_NAME}.conf"
if [[ -f "${OUT_CONF}" ]]; then
  echo "Client config already exists: ${OUT_CONF}" >&2
  exit 1
fi

SERVER_PUB_KEY_FILE="/etc/wireguard/${WG_IFACE}.server.pub"
if [[ ! -f "${SERVER_PUB_KEY_FILE}" ]]; then
  echo "Missing server public key: ${SERVER_PUB_KEY_FILE}" >&2
  exit 1
fi
SERVER_PUB_KEY="$(cat "${SERVER_PUB_KEY_FILE}")"

SERVER_NET_PREFIX="$(echo "${WG_NET}" | cut -d/ -f1)"
SERVER_NET_BASE="$(echo "${SERVER_NET_PREFIX}" | awk -F. '{print $1"."$2"."$3"."}')"

used_octets() {
  # Extract last octet from lines like: AllowedIPs = 10.66.66.2/32
  awk -v base="${SERVER_NET_BASE}" '
    $0 ~ /AllowedIPs[[:space:]]*=/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/32$/) {
          ip=$i
          sub(/\/32$/,"",ip)
          if (index(ip, base)==1) {
            split(ip, a, ".")
            print a[4]
          }
        }
      }
    }' "${CONF_FILE}" | sort -n | uniq
}

pick_octet() {
  local o
  # Reserve .1 for server; start clients at .2
  for o in $(seq 2 254); do
    if ! used_octets | grep -qx "${o}"; then
      echo "${o}"
      return 0
    fi
  done
  return 1
}

OCTET="$(pick_octet)"
if [[ -z "${OCTET}" ]]; then
  echo "No available client IPs in ${WG_NET}." >&2
  exit 1
fi

CLIENT_IP="${SERVER_NET_BASE}${OCTET}/32"

umask 077
CLIENT_PRIV_KEY="$(wg genkey)"
CLIENT_PUB_KEY="$(printf '%s' "${CLIENT_PRIV_KEY}" | wg pubkey)"
PRESHARED_KEY="$(wg genpsk)"

{
  echo
  echo "# client: ${CLIENT_NAME}"
  echo "[Peer]"
  echo "PublicKey = ${CLIENT_PUB_KEY}"
  echo "PresharedKey = ${PRESHARED_KEY}"
  echo "AllowedIPs = ${CLIENT_IP}"
} >>"${CONF_FILE}"

# Apply changes without dropping existing connections
wg syncconf "${WG_IFACE}" <(wg-quick strip "${WG_IFACE}")

cat >"${OUT_CONF}" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_IP}
DNS = ${WG_DNS}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${PRESHARED_KEY}
Endpoint = ${WG_HOST}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

chmod 600 "${OUT_CONF}"

echo "Created client: ${CLIENT_NAME}"
echo "Client config: ${OUT_CONF}"
echo
echo "To show a QR code in this terminal (good for iPhone):"
echo "  qrencode -t ansiutf8 < ${OUT_CONF}"


