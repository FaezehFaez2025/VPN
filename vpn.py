#!/usr/bin/env python3
"""
Simple VPN Server (Linux) and Client (macOS/Linux)
Requires: root/sudo privileges

WARNING: This is NOT a secure VPN (no encryption/authentication). Use only for learning/testing.
"""

import socket
import threading
import struct
import os
import sys
import fcntl
import subprocess
import platform


# ============== SERVER CODE (Linux only) ==============


class VPNServer:
    def __init__(self, port=5555, vpn_subnet="10.8.0"):
        self.port = port
        self.vpn_subnet = vpn_subnet
        self.server_vpn_ip = f"{vpn_subnet}.1"
        self.tun = None

    def create_tun(self):
        """Create TUN interface"""
        TUNSETIFF = 0x400454CA
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        self.tun = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", b"tun0", IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.tun, TUNSETIFF, ifr)

        subprocess.run(["ip", "addr", "add", f"{self.server_vpn_ip}/24", "dev", "tun0"], check=True)
        subprocess.run(["ip", "link", "set", "dev", "tun0", "up"], check=True)

        print(f"[+] TUN interface created: {self.server_vpn_ip}")

    def _default_iface_linux(self):
        r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        parts = r.stdout.strip().split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
        return "eth0"

    def setup_nat(self):
        """Setup NAT and IP forwarding"""
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)

        out_if = self._default_iface_linux()
        subprocess.run(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                f"{self.vpn_subnet}.0/24",
                "-o",
                out_if,
                "-j",
                "MASQUERADE",
            ],
            check=False,
        )
        subprocess.run(["iptables", "-A", "FORWARD", "-i", "tun0", "-j", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-A", "FORWARD", "-o", "tun0", "-j", "ACCEPT"], check=False)

        print(f"[+] NAT and IP forwarding configured (outbound interface: {out_if})")

    def tun_to_socket(self, sock):
        while True:
            try:
                data = os.read(self.tun, 2048)
                sock.sendall(struct.pack(">H", len(data)) + data)
            except Exception as e:
                print(f"[-] TUN to socket error: {e}")
                break

    def socket_to_tun(self, sock):
        buffer = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                buffer += data

                while len(buffer) >= 2:
                    pkt_len = struct.unpack(">H", buffer[:2])[0]
                    if len(buffer) < 2 + pkt_len:
                        break
                    packet = buffer[2 : 2 + pkt_len]
                    buffer = buffer[2 + pkt_len :]
                    os.write(self.tun, packet)
            except Exception as e:
                print(f"[-] Socket to TUN error: {e}")
                break

    def handle_client(self, conn, addr):
        print(f"[+] Client connected: {addr}")

        t1 = threading.Thread(target=self.tun_to_socket, args=(conn,), daemon=True)
        t2 = threading.Thread(target=self.socket_to_tun, args=(conn,), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        conn.close()
        print(f"[-] Client disconnected: {addr}")

    def start(self):
        if os.geteuid() != 0:
            print("[-] This script must be run as root!")
            sys.exit(1)

        self.create_tun()
        self.setup_nat()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", self.port))
        server.listen(1)

        print(f"[+] VPN Server listening on port {self.port}")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()


# ============== CLIENT CODE (macOS/Linux) ==============


class VPNClientMac:
    def __init__(self, server_ip, port=5555, vpn_subnet="10.8.0"):
        self.server_ip = server_ip
        self.port = port
        self.vpn_subnet = vpn_subnet
        self.client_vpn_ip = f"{vpn_subnet}.2"
        self.server_vpn_ip = f"{vpn_subnet}.1"
        self.tun = None
        self.sock = None
        self.tun_name = None

    def _list_utuns(self):
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        return [line.split(":")[0] for line in result.stdout.split("\n") if line.startswith("utun")]

    def create_tun(self):
        print("[*] Attempting to create utun interface...")
        existing_utuns = self._list_utuns()
        print(f"[*] Existing utun interfaces: {existing_utuns if existing_utuns else 'none'}")

        try:
            import ctypes
            import ctypes.util

            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

            # Declare function signatures (avoids pointer truncation on 64-bit macOS)
            libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
            libc.socket.restype = ctypes.c_int
            libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
            libc.ioctl.restype = ctypes.c_int
            libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            libc.connect.restype = ctypes.c_int
            libc.close.argtypes = [ctypes.c_int]
            libc.close.restype = ctypes.c_int

            PF_SYSTEM = 32
            AF_SYSTEM = 32
            SYSPROTO_CONTROL = 2
            AF_SYS_CONTROL = 2

            CTLIOCGINFO = 0xC0644E03
            UTUN_CONTROL_NAME = b"com.apple.net.utun_control"

            sock_fd = libc.socket(PF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
            if sock_fd < 0:
                raise OSError(f"Failed to create control socket, errno: {ctypes.get_errno()}")
            print(f"[+] Created control socket: {sock_fd}")

            class ctl_info(ctypes.Structure):
                _fields_ = [
                    ("ctl_id", ctypes.c_uint32),
                    ("ctl_name", ctypes.c_char * 96),
                ]

            info = ctl_info()
            info.ctl_id = 0
            info.ctl_name = UTUN_CONTROL_NAME  # ctypes will NUL-pad

            ctypes.set_errno(0)
            ret = libc.ioctl(sock_fd, ctypes.c_ulong(CTLIOCGINFO), ctypes.byref(info))
            if ret < 0:
                err = ctypes.get_errno()
                libc.close(sock_fd)
                raise OSError(f"ioctl(CTLIOCGINFO) failed, errno: {err}")

            if info.ctl_id == 0:
                libc.close(sock_fd)
                raise OSError("utun control not found (ctl_id=0)")

            print(f"[+] Got control ID: {info.ctl_id}")

            class sockaddr_ctl(ctypes.Structure):
                _fields_ = [
                    ("sc_len", ctypes.c_uint8),
                    ("sc_family", ctypes.c_uint8),
                    ("ss_sysaddr", ctypes.c_uint16),
                    ("sc_id", ctypes.c_uint32),
                    ("sc_unit", ctypes.c_uint32),
                    ("sc_reserved", ctypes.c_uint32 * 5),
                ]

            addr = sockaddr_ctl()
            addr.sc_len = ctypes.sizeof(sockaddr_ctl)
            addr.sc_family = AF_SYSTEM
            addr.ss_sysaddr = AF_SYS_CONTROL
            addr.sc_id = info.ctl_id
            addr.sc_unit = 0
            addr.sc_reserved = (ctypes.c_uint32 * 5)(0, 0, 0, 0, 0)

            ctypes.set_errno(0)
            ret = libc.connect(sock_fd, ctypes.byref(addr), ctypes.sizeof(addr))
            if ret < 0:
                err = ctypes.get_errno()
                libc.close(sock_fd)
                raise OSError(f"connect() to utun control failed, errno: {err}")

            print("[+] Connected to utun control")

            import time

            time.sleep(0.5)
            new_utuns = self._list_utuns()
            created = [u for u in new_utuns if u not in existing_utuns]
            self.tun_name = created[-1] if created else (new_utuns[-1] if new_utuns else "utun0")

            self.tun = sock_fd
            print(f"[+] Using interface: {self.tun_name}")

            subprocess.run(
                ["ifconfig", self.tun_name, "inet", self.client_vpn_ip, self.server_vpn_ip, "up"],
                check=True,
            )
            print(f"[+] TUN interface configured: {self.client_vpn_ip}")

        except Exception as e:
            print(f"[-] Failed to create utun interface: {e}")
            import traceback

            traceback.print_exc()
            sys.exit(1)

    def setup_routing(self):
        result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
        gateway = None
        for line in result.stdout.split("\n"):
            if "gateway:" in line:
                gateway = line.split(":", 1)[1].strip()
                break

        if gateway:
            subprocess.run(["route", "add", self.server_ip, gateway], check=False)

        subprocess.run(["route", "add", "-net", "0.0.0.0/1", self.server_vpn_ip], check=False)
        subprocess.run(["route", "add", "-net", "128.0.0.0/1", self.server_vpn_ip], check=False)
        print("[+] Routing configured - all traffic through VPN")

    def tun_to_socket(self):
        import select

        while True:
            try:
                ready = select.select([self.tun], [], [], 1.0)
                if ready[0]:
                    data = os.read(self.tun, 2048)
                    if len(data) > 4:
                        packet = data[4:]
                        self.sock.sendall(struct.pack(">H", len(packet)) + packet)
            except Exception as e:
                print(f"[-] TUN to socket error: {e}")
                break

    def socket_to_tun(self):
        buffer = b""
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buffer += data

                while len(buffer) >= 2:
                    pkt_len = struct.unpack(">H", buffer[:2])[0]
                    if len(buffer) < 2 + pkt_len:
                        break
                    packet = buffer[2 : 2 + pkt_len]
                    buffer = buffer[2 + pkt_len :]

                    header = struct.pack(">I", 2)  # AF_INET (IPv4)
                    os.write(self.tun, header + packet)
            except Exception as e:
                print(f"[-] Socket to TUN error: {e}")
                break

    def connect(self):
        if os.geteuid() != 0:
            print("[-] This script must be run as root!")
            sys.exit(1)

        self.create_tun()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.port))
        print(f"[+] Connected to VPN server: {self.server_ip}:{self.port}")

        self.setup_routing()

        t1 = threading.Thread(target=self.tun_to_socket, daemon=True)
        t2 = threading.Thread(target=self.socket_to_tun, daemon=True)
        t1.start()
        t2.start()

        print("[+] VPN tunnel active! (Ctrl+C to disconnect)")
        try:
            t1.join()
            t2.join()
        except KeyboardInterrupt:
            print("\n[*] Shutting down VPN tunnel...")
            try:
                if self.tun is not None:
                    os.close(self.tun)
            finally:
                if self.sock is not None:
                    self.sock.close()


class VPNClientLinux:
    def __init__(self, server_ip, port=5555, vpn_subnet="10.8.0"):
        self.server_ip = server_ip
        self.port = port
        self.vpn_subnet = vpn_subnet
        self.client_vpn_ip = f"{vpn_subnet}.2"
        self.server_vpn_ip = f"{vpn_subnet}.1"
        self.tun = None
        self.sock = None

    def create_tun(self):
        TUNSETIFF = 0x400454CA
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        self.tun = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", b"tun0", IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.tun, TUNSETIFF, ifr)

        subprocess.run(["ip", "addr", "add", f"{self.client_vpn_ip}/24", "dev", "tun0"], check=True)
        subprocess.run(["ip", "link", "set", "dev", "tun0", "up"], check=True)
        print(f"[+] TUN interface created: {self.client_vpn_ip}")

    def setup_routing(self):
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        gateway = result.stdout.split()[2]
        subprocess.run(["ip", "route", "add", f"{self.server_ip}/32", "via", gateway], check=False)
        subprocess.run(["ip", "route", "add", "0.0.0.0/1", "via", self.server_vpn_ip, "dev", "tun0"], check=False)
        subprocess.run(["ip", "route", "add", "128.0.0.0/1", "via", self.server_vpn_ip, "dev", "tun0"], check=False)
        print("[+] Routing configured - all traffic through VPN")

    def tun_to_socket(self):
        while True:
            try:
                data = os.read(self.tun, 2048)
                self.sock.sendall(struct.pack(">H", len(data)) + data)
            except Exception as e:
                print(f"[-] TUN to socket error: {e}")
                break

    def socket_to_tun(self):
        buffer = b""
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buffer += data

                while len(buffer) >= 2:
                    pkt_len = struct.unpack(">H", buffer[:2])[0]
                    if len(buffer) < 2 + pkt_len:
                        break
                    packet = buffer[2 : 2 + pkt_len]
                    buffer = buffer[2 + pkt_len :]
                    os.write(self.tun, packet)
            except Exception as e:
                print(f"[-] Socket to TUN error: {e}")
                break

    def connect(self):
        if os.geteuid() != 0:
            print("[-] This script must be run as root!")
            sys.exit(1)

        self.create_tun()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.port))
        print(f"[+] Connected to VPN server: {self.server_ip}:{self.port}")

        self.setup_routing()

        t1 = threading.Thread(target=self.tun_to_socket, daemon=True)
        t2 = threading.Thread(target=self.socket_to_tun, daemon=True)
        t1.start()
        t2.start()

        print("[+] VPN tunnel active!")
        t1.join()
        t2.join()


# ============== MAIN ==============


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Server: sudo python3 vpn.py server")
        print("  Client: sudo python3 vpn.py client <server_ip>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "server":
        VPNServer(port=5555).start()
    elif mode == "client":
        if len(sys.argv) < 3:
            print("Error: Server IP required for client mode")
            sys.exit(1)

        if platform.system() == "Darwin":
            print("[*] Detected macOS - using utun interface")
            VPNClientMac(server_ip=sys.argv[2], port=5555).connect()
        else:
            print("[*] Detected Linux - using tun interface")
            VPNClientLinux(server_ip=sys.argv[2], port=5555).connect()
    else:
        print("Invalid mode. Use 'server' or 'client'")
        sys.exit(1)


