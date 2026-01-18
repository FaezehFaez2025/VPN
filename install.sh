#!/usr/bin/env bash
set -euo pipefail

# Self-hosted WireGuard server setup for Debian/Ubuntu.
# Creates /etc/wireguard/wg0.conf and one initial client config.

WG_IFACE="${WG_IFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_NET="${WG_NET:-10.66.66.0/24}"
WG_SERVER_IP="${WG_SERVER_IP:-10.66.66.1/24}"
WG_DNS="${WG_DNS:-1.1.1.1}"
FIRST_CLIENT_NAME="${FIRST_CLIENT_NAME:-client1}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

if [[ -f "/etc/wireguard/${WG_IFACE}.conf" ]]; then
  echo "/etc/wireguard/${WG_IFACE}.conf already exists; refusing to overwrite." >&2
  echo "If you really want to redo from scratch, move it away first." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# NOTE: Do NOT install "resolvconf" here.
# On Debian 12, pulling in resolvconf can remove/disable systemd-resolved and break DNS
# (e.g. "curl: (6) Could not resolve host ..."). The server wg0 config does not need it.
apt-get install -y --no-install-recommends \
  wireguard \
  iptables \
  qrencode \
  curl \
  ca-certificates

OUT_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)"
if [[ -z "${OUT_IFACE}" ]]; then
  echo "Could not detect default network interface (OUT_IFACE)." >&2
  exit 1
fi

WG_HOST="$(curl -4fsSL https://api.ipify.org || true)"
if [[ -z "${WG_HOST}" ]]; then
  # Fallback: use the primary IPv4 on OUT_IFACE (may be private behind NAT).
  WG_HOST="$(ip -4 -o addr show dev "${OUT_IFACE}" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
fi
if [[ -z "${WG_HOST}" ]]; then
  echo "Could not determine public IP/host for Endpoint (WG_HOST)." >&2
  exit 1
fi

umask 077
mkdir -p /etc/wireguard

SERVER_PRIV_KEY_FILE="/etc/wireguard/${WG_IFACE}.server.key"
SERVER_PUB_KEY_FILE="/etc/wireguard/${WG_IFACE}.server.pub"
if [[ ! -f "${SERVER_PRIV_KEY_FILE}" ]]; then
  wg genkey | tee "${SERVER_PRIV_KEY_FILE}" | wg pubkey > "${SERVER_PUB_KEY_FILE}"
fi
SERVER_PRIV_KEY="$(cat "${SERVER_PRIV_KEY_FILE}")"
SERVER_PUB_KEY="$(cat "${SERVER_PUB_KEY_FILE}")"

# Enable forwarding
cat >/etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null

# Persist parameters for add-client.sh
cat >/etc/wireguard/${WG_IFACE}.params <<EOF
WG_IFACE=${WG_IFACE}
WG_PORT=${WG_PORT}
WG_NET=${WG_NET}
WG_SERVER_IP=${WG_SERVER_IP}
WG_DNS=${WG_DNS}
OUT_IFACE=${OUT_IFACE}
WG_HOST=${WG_HOST}
EOF

# Create server config
cat >/etc/wireguard/${WG_IFACE}.conf <<EOF
[Interface]
Address = ${WG_SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
SaveConfig = false

# NAT + forwarding (IPv4)
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -A FORWARD -o %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${OUT_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${OUT_IFACE} -j MASQUERADE
EOF

chmod 600 "/etc/wireguard/${WG_IFACE}.conf"

# Start and enable
systemctl enable --now "wg-quick@${WG_IFACE}"

# Create first client
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "${SCRIPT_DIR}/add-client.sh" "${FIRST_CLIENT_NAME}"

echo
echo "Server is up."
echo "Server public key: ${SERVER_PUB_KEY}"
echo "Endpoint for clients: ${WG_HOST}:${WG_PORT}"
echo
echo "If your provider firewall is enabled, allow UDP/${WG_PORT} inbound to this server."
echo "To see status: wg show"


