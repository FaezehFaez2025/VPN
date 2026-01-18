# WireGuard VPN (server) — command checklist

## Fresh server: install requirements

```bash
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl \
  wireguard iptables qrencode
```

## Install / bring up VPN

```bash
cd /root/VPN
sudo bash install.sh
```

## Firewall (required)

Cloud/provider firewall: allow **inbound UDP/51820** to this server.

If you use a local firewall:

### Option A: `ufw` (install if missing)

```bash
sudo apt-get update -y
sudo apt-get install -y ufw
sudo ufw allow 51820/udp
sudo ufw enable
sudo ufw status verbose
```

### Option B: no local firewall (`ufw` not installed)

Nothing to run locally; just ensure your cloud/provider firewall allows UDP/51820.

## Add client(s)

```bash
cd /root/VPN
sudo bash add-client.sh laptop
sudo bash add-client.sh iphone
```

Client configs:

```bash
ls -lah /root/VPN/clients/
```

## Export client config / QR code

Copy to your laptop:

```bash
scp root@YOUR_SERVER_IP:/root/VPN/clients/iphone.conf .
```

Print in terminal:

```bash
sudo cat /root/VPN/clients/iphone.conf
```

Show QR (iPhone WireGuard app → “Create from QR code”):

```bash
qrencode -t ansiutf8 < /root/VPN/clients/iphone.conf
```

## Verify

Server:

```bash
sudo systemctl --no-pager --full status wg-quick@wg0
sudo wg show
sudo ss -ulnp | grep -E ':(51820)\\b' || true
```

Client (after connecting):

```bash
curl -4 https://api.ipify.org
```

## Reset / uninstall (server)

```bash
sudo systemctl disable --now wg-quick@wg0 || true
sudo rm -f /etc/wireguard/wg0.conf /etc/wireguard/wg0.params /etc/wireguard/wg0.server.key /etc/wireguard/wg0.server.pub
sudo rm -f /etc/sysctl.d/99-wireguard.conf
sudo rm -f /root/VPN/clients/*.conf
sudo sysctl --system >/dev/null
```
