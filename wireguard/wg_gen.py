#!/usr/bin/env python3
"""
WireGuard config generator (server + clients).

Runs on the Linux server and uses the `wg` CLI to generate keys.
Output:
  ./out/server/wg0.conf
  ./out/clients/<name>.conf
  ./out/keys/*
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
from dataclasses import dataclass
from typing import Iterable


DEFAULT_VPN_CIDR = "10.8.0.0/24"
DEFAULT_SERVER_IP = "10.8.0.1/24"
DEFAULT_PORT = 51820


def _run(cmd: list[str], *, input_bytes: bytes | None = None) -> bytes:
    return subprocess.check_output(cmd, input=input_bytes)


def wg_genkey() -> str:
    return _run(["wg", "genkey"]).decode().strip()


def wg_pubkey(private_key: str) -> str:
    return _run(["wg", "pubkey"], input_bytes=(private_key + "\n").encode()).decode().strip()


def _ensure_dir(p: pathlib.Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _write_text(path: pathlib.Path, data: str, mode: int = 0o600) -> None:
    _ensure_dir(path.parent)
    path.write_text(data, encoding="utf-8")
    os.chmod(path, mode)


@dataclass(frozen=True)
class ClientSpec:
    name: str
    ip: str  # e.g. "10.8.0.2/32"


def _alloc_clients(names: Iterable[str], base: str = "10.8.0") -> list[ClientSpec]:
    # Start at .2 (server is .1)
    out: list[ClientSpec] = []
    host = 2
    for n in names:
        n2 = n.strip()
        if not n2:
            continue
        out.append(ClientSpec(name=n2, ip=f"{base}.{host}/32"))
        host += 1
    if not out:
        raise SystemExit("No clients specified. Use --clients mac,iphone (or similar).")
    return out


def _server_conf(
    *,
    server_private: str,
    listen_port: int,
    server_address: str,
    vpn_cidr: str,
    wan_iface: str,
    peers: list[tuple[str, str]],  # (client_pub, client_ip/32)
) -> str:
    # PostUp/Down rules use iptables for broad compatibility.
    postup = (
        "sysctl -w net.ipv4.ip_forward=1; "
        f"iptables -t nat -A POSTROUTING -s {vpn_cidr} -o {wan_iface} -j MASQUERADE; "
        "iptables -A FORWARD -i %i -j ACCEPT; "
        "iptables -A FORWARD -o %i -j ACCEPT"
    )
    postdown = (
        f"iptables -t nat -D POSTROUTING -s {vpn_cidr} -o {wan_iface} -j MASQUERADE; "
        "iptables -D FORWARD -i %i -j ACCEPT; "
        "iptables -D FORWARD -o %i -j ACCEPT"
    )

    lines: list[str] = [
        "[Interface]",
        f"Address = {server_address}",
        f"ListenPort = {listen_port}",
        f"PrivateKey = {server_private}",
        f"PostUp = {postup}",
        f"PostDown = {postdown}",
        "",
    ]
    for client_pub, client_ip32 in peers:
        lines += [
            "[Peer]",
            f"PublicKey = {client_pub}",
            f"AllowedIPs = {client_ip32}",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def _client_conf(
    *,
    client_private: str,
    client_address: str,
    server_public: str,
    endpoint: str,
    allowed_ips: str,
    dns: str | None,
) -> str:
    lines: list[str] = [
        "[Interface]",
        f"PrivateKey = {client_private}",
        f"Address = {client_address}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public}",
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {allowed_ips}",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate WireGuard server + client configs.")
    ap.add_argument("--endpoint", required=True, help="Server public IP or DNS name (clients connect to this).")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="UDP port (default: 51820).")
    ap.add_argument("--vpn-cidr", default=DEFAULT_VPN_CIDR, help="VPN subnet CIDR (default: 10.8.0.0/24).")
    ap.add_argument("--server-address", default=DEFAULT_SERVER_IP, help="Server interface address (default: 10.8.0.1/24).")
    ap.add_argument("--wan-iface", default="eth0", help="Server outbound interface for NAT (default: eth0).")
    ap.add_argument("--clients", default="mac,iphone", help="Comma-separated client names (default: mac,iphone).")
    ap.add_argument("--dns", default="1.1.1.1", help="DNS for clients (default: 1.1.1.1). Use empty to omit.")
    ap.add_argument(
        "--split-tunnel",
        action="store_true",
        help="If set, route only the VPN subnet via tunnel (otherwise full-tunnel).",
    )
    ap.add_argument("--out-dir", default=str(pathlib.Path(__file__).parent / "out"), help="Output directory.")
    args = ap.parse_args()

    # Basic sanity: this script expects wg to exist.
    if subprocess.call(["which", "wg"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        raise SystemExit("WireGuard tools not found. Install `wireguard` package (must provide `wg`).")

    out_dir = pathlib.Path(args.out_dir).resolve()
    server_dir = out_dir / "server"
    clients_dir = out_dir / "clients"
    keys_dir = out_dir / "keys"
    _ensure_dir(server_dir)
    _ensure_dir(clients_dir)
    _ensure_dir(keys_dir)

    base = args.vpn_cidr.split("/")[0].rsplit(".", 1)[0]  # "10.8.0"
    client_names = [c.strip() for c in args.clients.split(",")]
    clients = _alloc_clients(client_names, base=base)

    server_priv = wg_genkey()
    server_pub = wg_pubkey(server_priv)
    _write_text(keys_dir / "server_private.key", server_priv + "\n")
    _write_text(keys_dir / "server_public.key", server_pub + "\n", mode=0o644)

    endpoint = f"{args.endpoint}:{args.port}"
    allowed_ips = (args.vpn_cidr if args.split_tunnel else "0.0.0.0/0, ::/0")
    dns = args.dns if args.dns.strip() else None

    peers: list[tuple[str, str]] = []
    for c in clients:
        c_priv = wg_genkey()
        c_pub = wg_pubkey(c_priv)
        _write_text(keys_dir / f"{c.name}_private.key", c_priv + "\n")
        _write_text(keys_dir / f"{c.name}_public.key", c_pub + "\n", mode=0o644)

        peers.append((c_pub, c.ip))

        c_conf = _client_conf(
            client_private=c_priv,
            client_address=c.ip,
            server_public=server_pub,
            endpoint=endpoint,
            allowed_ips=allowed_ips,
            dns=dns,
        )
        _write_text(clients_dir / f"{c.name}.conf", c_conf, mode=0o600)

    s_conf = _server_conf(
        server_private=server_priv,
        listen_port=args.port,
        server_address=args.server_address,
        vpn_cidr=args.vpn_cidr,
        wan_iface=args.wan_iface,
        peers=peers,
    )
    _write_text(server_dir / "wg0.conf", s_conf, mode=0o600)

    print(f"[+] Wrote: {server_dir / 'wg0.conf'}")
    print(f"[+] Wrote clients: {clients_dir}")
    print(f"[+] Keys: {keys_dir}")
    print("")
    print("Next (server):")
    print("  sudo install -d -m 0755 /etc/wireguard")
    print(f"  sudo install -m 0600 {server_dir / 'wg0.conf'} /etc/wireguard/wg0.conf")
    print("  sudo systemctl enable --now wg-quick@wg0")
    print("")
    print("Next (clients): import the .conf files into the WireGuard app.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


