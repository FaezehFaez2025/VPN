# Self-hosted VPN on this server (WireGuard)

This repo folder contains scripts to run a **WireGuard VPN** on this server. Your laptop/iPhone can connect to it, and then your public IP on the internet becomes **this server’s public IP** (so sites “think you’re in” the server’s country).

## Install / bring up VPN (server)

On the server:

```bash
cd /root/VPN
sudo bash install.sh
```

This will:

- Install WireGuard tools
- Enable IP forwarding
- Create `/etc/wireguard/wg0.conf`
- Start and enable `wg-quick@wg0`
- Create an initial client config under `/root/VPN/clients/`

<details>
<summary><strong>Optional: verify the install (server-side) + fix DNS if needed</strong></summary>

On the server:

```bash
sudo systemctl --no-pager --full status wg-quick@wg0
sudo wg show
sudo ss -ulnp | grep -E ':(51820)\\b' || true
```

If the server loses DNS (example: `curl: (6) Could not resolve host`)

On Debian 12, installing `resolvconf` can remove/disable `systemd-resolved`, which can break DNS.

Quick fix (set resolv.conf)

```bash
sudo sh -c 'printf "nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n" > /etc/resolv.conf'
```

Then verify:

```bash
getent hosts api.ipify.org
curl -4 https://api.ipify.org
```

Make it persistent (recommended)

Reinstall and re-enable systemd-resolved:

```bash
sudo apt-get update -y
sudo apt-get install -y systemd-resolved
sudo systemctl enable --now systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

</details>

## Add a new client (laptop, iPhone, etc.)

```bash
cd /root/VPN
sudo bash add-client.sh laptop
sudo bash add-client.sh iphone
```

Client configs are saved at:

- `/root/VPN/clients/<name>.conf`

## iPhone setup

- Install the **WireGuard** app (iOS App Store)
- WireGuard app → **Add a tunnel** → **Create from QR code**

To print a QR code in the server terminal:

```bash
qrencode -t ansiutf8 < /root/VPN/clients/iphone.conf
```

## Laptop setup

- Install WireGuard:
  - macOS: WireGuard app
  - Windows: WireGuard app
  - Linux: `wireguard-tools`
- Import the `<name>.conf` file and connect.

## Verify it worked

On the client (after connecting), visit an “IP check” site or run:

```bash
curl -4 https://api.ipify.org
```

It should return **this server’s** public IP.

## Notes / common issues

- **Provider firewall**: the script cannot open your cloud firewall for you. You must allow inbound UDP to the WireGuard port.
- **IPv6 leak**: this setup is IPv4-only. If your client has IPv6, some traffic may go outside the VPN unless you disable IPv6 on the client or extend the setup for IPv6.


