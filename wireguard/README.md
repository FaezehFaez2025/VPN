## WireGuard VPN (recommended)

This is a **real VPN** approach (encrypted + authenticated) using **WireGuard**, meant to replace the insecure learning script in `../vpn.py`.

### What you’ll get

- A Linux server config: `out/server/wg0.conf`
- Two client configs you can import:
  - `out/clients/mac.conf` (macOS laptop)
  - `out/clients/iphone.conf` (iPhone)

### 1) Server (Linux VPS) prerequisites

Install WireGuard + a firewall tool (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y wireguard
```

#### Open the “VPN port” (UDP 51820)

WireGuard listens on **UDP 51820**. You must allow inbound UDP 51820 to your VPS (and keep SSH allowed).

If you don’t have `ufw` installed yet:

```bash
sudo apt update
sudo apt install -y ufw

# IMPORTANT: allow SSH first so you don't lock yourself out
sudo ufw allow OpenSSH

# allow WireGuard
sudo ufw allow 51820/udp

# turn firewall on
sudo ufw enable
sudo ufw status
```

Also check your VPS provider “cloud firewall / security group” (if you have one) and ensure it allows:
- UDP 51820 inbound
- TCP 22 inbound (SSH)

### 2) Generate configs (run on the server)

#### Find your outbound network interface name (usually `eth0` or `ens3`)

```bash
ip route show default
```

Example output includes `dev eth0` → your `--wan-iface` is `eth0`.

#### Generate configs (server + Mac + iPhone)

Run on the VPS (example uses your server IP):

```bash
cd /root/VPN/wireguard
sudo python3 wg_gen.py --endpoint 104.234.95.201 --wan-iface eth0
```

This creates configs under `./out/`.

### 3) Bring up the VPN on the server

Copy the generated server config into place and start it:

```bash
sudo install -d -m 0755 /etc/wireguard
sudo install -m 0600 ./out/server/wg0.conf /etc/wireguard/wg0.conf

sudo systemctl enable --now wg-quick@wg0
sudo systemctl status wg-quick@wg0 --no-pager
sudo wg show
```

### 4) Import on macOS

Copy the config from the VPS to your Mac (run on your Mac):

```bash
scp root@104.234.95.201:/root/VPN/wireguard/out/clients/mac.conf .
```

Then on macOS:
- Install the **WireGuard** app
- Import `mac.conf`
- Toggle it **ON**

Test on macOS:

```bash
curl ifconfig.me
```

It should print your VPS IP (example: `104.234.95.201`).

### 5) Import on iPhone (easiest: QR code)

Install the **WireGuard** iOS app, then on the server:

```bash
sudo apt install -y qrencode
cd /root/VPN/wireguard
./show_qr.sh ./out/clients/iphone.conf
```

In the iPhone WireGuard app: **Add a Tunnel** → **Create from QR Code** → scan.

### Notes / knobs

- **Full tunnel**: client configs default to `AllowedIPs = 0.0.0.0/0, ::/0` (all traffic through VPN).
- **Split tunnel**: re-run the generator with `--split-tunnel` to only route the VPN subnet through the tunnel.


