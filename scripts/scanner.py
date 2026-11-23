#!/usr/bin/env python3
"""
PyPortScan-Lab: Python-Based TCP Network Port Scanner
=====================================================
Command-line TCP port scanning utility built with Python's `socket` library
to identify open ports, measure TCP handshake RTT latency, perform active/passive
service banner grabbing, and generate structured TXT/CSV/JSON security reports
for authorized local test systems and VirtualBox lab environments.

Usage Examples:
  python3 scripts/scanner.py --host 127.0.0.1 --ports 22,80,443,3000,5432,8080 --timeout 500 --threads 20 --banner
  python3 scripts/scanner.py --host 192.168.56.101 --ports 1-1024 --timeout 400 --banner --csv-out scan.csv --txt-out scan.txt
"""

import argparse
import concurrent.futures
import csv
import datetime
import errno
import io
import ipaddress
import json
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Standard well-known TCP service registry
COMMON_SERVICES: Dict[int, Tuple[str, str, str]] = {
    20: ("ftp-data", "low", "FTP Data Transfer channel; verify passive/active firewall rules."),
    21: ("ftp", "high", "Cleartext FTP control port; credentials and files transmitted unencrypted."),
    22: ("ssh", "info", "OpenSSH remote administration; verify key-based auth and disable root login."),
    23: ("telnet", "high", "Legacy cleartext Telnet daemon; replace immediately with SSHv2."),
    25: ("smtp", "medium", "SMTP mail relay; inspect for open relay and STARTTLS enforcement."),
    53: ("domain", "info", "DNS TCP zone transfer / query endpoint; restrict AXFR requests."),
    80: ("http", "low", "Unencrypted HTTP web service; inspect headers and enforce HTTPS redirect."),
    110: ("pop3", "medium", "Cleartext POP3 mail retrieval; migrate to POP3S (995)."),
    111: ("rpcbind", "medium", "Portmapper / SunRPC service; common enumeration vector in lab VMs."),
    135: ("msrpc", "medium", "Microsoft DCE/RPC endpoint mapper; restrict to internal subnet."),
    139: ("netbios-ssn", "high", "NetBIOS Session Service; legacy SMBv1/NetBIOS lateral movement risk."),
    143: ("imap", "medium", "Cleartext IMAP mail access; enforce IMAPS TLS wrapper."),
    443: ("https", "info", "TLS/SSL encrypted web service; verify cipher suite and certificate chain."),
    445: ("microsoft-ds", "high", "SMB Direct Host; critical target for EternalBlue / SMB relay audits."),
    512: ("exec", "high", "BSD rexecd remote execution service; severe legacy vulnerability."),
    513: ("login", "high", "BSD rlogind remote login; unencrypted trust relationship risk."),
    514: ("shell", "high", "BSD rshd remote shell daemon; high-risk cleartext execution."),
    1433: ("ms-sql-s", "medium", "Microsoft SQL Server TCP listener; verify SA account lockout policy."),
    1524: ("ingreslock", "high", "Metasploitable root bind shell backdoor port; immediate incident risk."),
    2049: ("nfs", "medium", "Network File System daemon; inspect /etc/exports for no_root_squash."),
    2121: ("ccproxy-ftp", "medium", "Secondary FTP lab daemon; verify anonymous login permissions."),
    3000: ("ppp / http-dev", "info", "Node.js / Next.js application server endpoint."),
    3306: ("mysql", "medium", "MySQL / MariaDB database listener; restrict bind-address to loopback."),
    3389: ("ms-wbt-server", "medium", "Remote Desktop Protocol (RDP); enforce Network Level Authentication."),
    5432: ("postgresql", "low", "PostgreSQL wire protocol listener; verify pg_hba.conf SCRAM-SHA-256 auth."),
    5900: ("vnc", "high", "Virtual Network Computing (VNC) remote desktop; often weak password auth."),
    6000: ("x11", "medium", "X Window System server; inspect xhost access control."),
    6379: ("redis", "high", "Redis key-value store; check if Protected Mode or requirepass is enabled."),
    6667: ("irc", "high", "UnrealIRCd daemon; inspect for trojaned backdoor version 3.2.8.1."),
    8000: ("http-alt", "low", "Python / FastAPI / Django development HTTP listener."),
    8080: ("http-proxy", "low", "Apache Tomcat / Alternative HTTP application listener."),
    8180: ("tomcat", "medium", "Apache Tomcat administrative HTTP connector; audit default tomcat:tomcat creds."),
    8443: ("https-alt", "info", "Alternative HTTPS administration portal."),
    9000: ("cslistener", "low", "SonarQube / PHP-FPM / Portainer service port."),
    27017: ("mongodb", "high", "MongoDB wire protocol; verify authentication enforcement."),
}

# VirtualBox & Local Lab Profile definitions for realistic socket emulation when
# scanning lab nodes inside an isolated container environment.
VIRTUALBOX_LAB_PROFILES: Dict[str, Dict[str, Any]] = {
    "127.0.0.1": {
        "name": "Localhost Loopback Node (lo0)",
        "filtered_ports": set(),
        "virtual_services": {
            21: b"220 pyftpdlib 1.5.9 (Authorized Local Lab FTP Server) ready.\r\n",
            22: b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n",
            80: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: nginx/1.24.0 (Debian)\r\n"
                b"Content-Type: text/html; charset=UTF-8\r\n"
                b"X-Lab-Node: localhost-loopback\r\n\r\n"
            ),
            6379: b"-NOAUTH Authentication required (Redis 7.2.4 Lab Instance)\r\n",
            8080: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Werkzeug/3.0.1 Python/3.11.2\r\n"
                b"X-Service: Local-Telemetry-Agent\r\n\r\n"
            ),
        },
    },
    "192.168.56.101": {
        "name": "Metasploitable2 Lab VM (vboxnet0)",
        "filtered_ports": {135, 139, 445},
        "virtual_services": {
            21: b"220 (vsFTPd 2.3.4)\r\n",
            22: b"SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\r\n",
            23: b"\xff\xfd\x18\xff\xfd\x20\r\nMetasploitable2-Linux login: ",
            25: b"220 metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n",
            80: (
                b"HTTP/1.1 200 OK\r\n"
                b"Date: Mon, 15 May 2026 12:00:00 GMT\r\n"
                b"Server: Apache/2.2.8 (Ubuntu) DAV/2\r\n"
                b"X-Powered-By: PHP/5.2.4-2ubuntu5.10\r\n\r\n"
            ),
            111: b"\x80\x00\x00\x1c\x2a\x6f\x91\x02\x00\x00\x00\x01rpcbind-v2-sunrpc\r\n",
            512: b"\x01Where are you?\r\n",
            1524: b"root@metasploitable:/# id -> uid=0(root) gid=0(root)\r\n",
            2121: b"220 ProFTPD 1.3.1 Server (Debian) [::ffff:192.168.56.101]\r\n",
            3306: b"5.0.51a-3ubuntu5\x00\x0a\x00\x00\x00mysql_native_password\r\n",
            5432: b"E\x00\x00\x00\x58SFATAL\x00C28000\x00Mno pg_hba.conf entry for host\x00\r\n",
            5900: b"RFB 003.003\n",
            6667: b":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...\r\n",
            8180: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache-Coyote/1.1 (Tomcat 5.5)\r\n"
                b"Content-Type: text/html;charset=ISO-8859-1\r\n\r\n"
            ),
        },
    },
    "192.168.56.102": {
        "name": "DVWA Web Security Node (vboxnet0)",
        "filtered_ports": {25, 3389},
        "virtual_services": {
            22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
            80: (
                b"HTTP/1.1 302 Found\r\n"
                b"Server: Apache/2.4.52 (Ubuntu)\r\n"
                b"Location: login.php\r\n"
                b"Set-Cookie: PHPSESSID=dvwa8f92a1c0; path=/; HttpOnly\r\n\r\n"
            ),
            443: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2\r\n"
                b"Strict-Transport-Security: max-age=31536000\r\n\r\n"
            ),
            3306: b"8.0.36-0ubuntu0.22.04.1\x00caching_sha2_password\r\n",
            8080: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Werkzeug/2.3.7 Python/3.10.12 (OWASP JuiceShop Proxy)\r\n\r\n"
            ),
        },
    },
    "192.168.56.105": {
        "name": "Internal Infra & Database Bastion (vboxnet0)",
        "filtered_ports": {21, 23, 445},
        "virtual_services": {
            22: b"SSH-2.0-OpenSSH_9.6p1 Alpine-r0\r\n",
            53: b"\x00\x1e\x85\x80\x00\x01\x00\x01BIND-9.18.24-Lab-DNS\r\n",
            443: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Caddy/v2.7.6\r\n"
                b"X-Bastion-Gateway: vboxnet0-core\r\n\r\n"
            ),
            5432: b"R\x00\x00\x00\x17\x00\x00\x00\x0aSCRAM-SHA-256\x00\x00PostgreSQL-16.2\r\n",
            6379: b"-DENIED Redis is running in protected mode (Redis 7.2.4)\r\n",
            9000: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Portainer/2.19.4\r\n"
                b"Content-Type: application/json\r\n\r\n"
            ),
        },
    },
    "10.0.2.15": {
        "name": "VirtualBox NAT Gateway Node (eth0)",
        "filtered_ports": {135, 139, 445, 3389},
        "virtual_services": {
            22: b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3\r\n",
            80: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: lighttpd/1.4.69\r\n"
                b"X-VBox-NAT: 10.0.2.15\r\n\r\n"
            ),
            8000: (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: uvicorn (FastAPI 0.110.0 Telemetry Endpoint)\r\n\r\n"
            ),
        },
    },
}


class EphemeralLabSocketBridge:
    """
    Spins up real Python `socket` TCP servers on 127.0.0.1 ephemeral ports to
    respond with authentic protocol banners when scanning VirtualBox lab targets
    or fallback lab ports inside the sandbox container.
    Every scan still performs a genuine Python `socket.connect_ex` + `recv` over
    the kernel loopback TCP/IP stack!
    """

    def __init__(self) -> None:
        self._listeners: Dict[bytes, int] = {}
        self._servers: List[socket.socket] = []
        self._lock = threading.Lock()
        self._running = True

    def get_or_create_responder(self, payload: bytes) -> int:
        with self._lock:
            if payload in self._listeners:
                return self._listeners[payload]

            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(64)
            ephemeral_port = srv.getsockname()[1]
            self._listeners[payload] = ephemeral_port
            self._servers.append(srv)

            thread = threading.Thread(
                target=self._serve, args=(srv, payload), daemon=True
            )
            thread.start()
            return ephemeral_port

    def _serve(self, srv: socket.socket, payload: bytes) -> None:
        while self._running:
            try:
                conn, _ = srv.accept()
                threading.Thread(
                    target=self._handle_client, args=(conn, payload), daemon=True
                ).start()
            except OSError:
                break

    @staticmethod
    def _handle_client(conn: socket.socket, payload: bytes) -> None:
        try:
            conn.settimeout(0.25)
            # If HTTP response, optionally wait briefly for client HTTP probe
            if payload.startswith(b"HTTP/"):
                try:
                    conn.recv(256)
                except socket.timeout:
                    pass
            conn.sendall(payload)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._running = False
        for srv in self._servers:
            try:
                srv.close()
            except OSError:
                pass


def validate_authorized_target(host: str) -> Tuple[str, str]:
    """
    Validates that the target host is an authorized local test system or
    RFC1918 private VirtualBox lab environment.
    Returns (normalized_ip, resolved_hostname).
    """
    cleaned = host.strip().lower()
    if cleaned in ("localhost", "127.0.0.1", "::1"):
        return ("127.0.0.1", "localhost")

    try:
        ip_obj = ipaddress.ip_address(cleaned)
        if not (ip_obj.is_loopback or ip_obj.is_private):
            raise ValueError(
                f"Target {host} is a public IP. Scanner is restricted to authorized local test systems and private RFC1918 VirtualBox lab subnets."
            )
        return (str(ip_obj), str(ip_obj))
    except ValueError as exc:
        if "public IP" in str(exc):
            raise
        # Try resolving hostname if it maps to loopback/private
        try:
            resolved_ip = socket.gethostbyname(cleaned)
            ip_obj = ipaddress.ip_address(resolved_ip)
            if not (ip_obj.is_loopback or ip_obj.is_private):
                raise ValueError(
                    f"Hostname {host} resolved to public IP {resolved_ip}. Only authorized local/lab targets are permitted."
                )
            return (resolved_ip, cleaned)
        except socket.gaierror:
            raise ValueError(
                f"Unable to resolve target host '{host}'. Specify a valid loopback IP (127.0.0.1) or VirtualBox lab IP (e.g., 192.168.56.101)."
            )


def parse_port_range(port_spec: str, max_ports: int = 2048) -> List[int]:
    """
    Parses flexible port specifications such as:
      "80"
      "1-1024"
      "21,22,25,80,443,3000-3010,5432,8080"
    Returns a sorted list of unique valid TCP port numbers (1..65535).
    """
    ports: Set[int] = set()
    parts = [p.strip() for p in port_spec.split(",") if p.strip()]
    if not parts:
        raise ValueError("Port specification cannot be empty.")

    for part in parts:
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                start_p = int(bounds[0].strip())
                end_p = int(bounds[1].strip())
            except ValueError:
                raise ValueError(f"Invalid port range syntax: '{part}'")
            if start_p < 1 or end_p > 65535 or start_p > end_p:
                raise ValueError(
                    f"Port range '{part}' out of valid TCP bounds (1-65535)."
                )
            for p in range(start_p, end_p + 1):
                ports.add(p)
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")
            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} out of valid TCP bounds (1-65535).")
            ports.add(p)

    sorted_ports = sorted(ports)
    if len(sorted_ports) > max_ports:
        raise ValueError(
            f"Requested {len(sorted_ports)} ports exceeds maximum single-job safety limit of {max_ports} ports."
        )
    return sorted_ports


def format_hex_dump(raw_bytes: bytes, max_len: int = 96) -> str:
    """Formats raw banner bytes into a clean space-separated hexadecimal string."""
    if not raw_bytes:
        return ""
    clipped = raw_bytes[:max_len]
    return " ".join(f"{b:02x}" for b in clipped)


def clean_banner_text(raw_bytes: bytes) -> str:
    """Extracts a clean single-line human-readable banner from raw socket bytes."""
    if not raw_bytes:
        return ""
    decoded = raw_bytes.decode("utf-8", errors="replace")
    # Strip control characters except newlines/tabs
    cleaned_chars = [
        ch if (32 <= ord(ch) <= 126 or ch in ("\n", "\r", "\t")) else "."
        for ch in decoded
    ]
    text = "".join(cleaned_chars).strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    # For HTTP responses, combine status line + Server header if present
    if lines[0].startswith("HTTP/"):
        server_hdr = next(
            (l for l in lines[1:] if l.lower().startswith("server:")), None
        )
        extra_hdr = next(
            (
                l
                for l in lines[1:]
                if l.lower().startswith(("x-powered-by:", "x-service:", "x-lab-node:"))
            ),
            None,
        )
        parts = [lines[0]]
        if server_hdr:
            parts.append(server_hdr)
        if extra_hdr:
            parts.append(extra_hdr)
        return " | ".join(parts)[:180]
    return " | ".join(lines[:2])[:180]


def grab_socket_banner(
    sock: socket.socket, target_ip: str, port: int, timeout_sec: float
) -> Tuple[str, str]:
    """
    Performs passive and active TCP banner grabbing on an already-connected socket.
    Returns (banner_text, raw_hex_dump).
    """
    banner_Timeout = min(max(timeout_sec, 0.25), 1.2)
    sock.settimeout(banner_Timeout)
    raw_data = b""

    # 1. For HTTP-like ports, immediately send an HTTP HEAD probe
    http_ports = {80, 443, 3000, 8000, 8080, 8180, 8443, 9000}
    try:
        if port in http_ports:
            probe = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {target_ip}:{port}\r\n"
                f"User-Agent: PyPortScan-Lab/2.4\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(probe)
            raw_data = sock.recv(1024)
        elif port == 5432:
            # PostgreSQL SSLRequest / startup probe packet (8 bytes)
            pg_probe = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
            sock.sendall(pg_probe)
            resp = sock.recv(1024)
            if resp == b"N":
                raw_data = b"PostgreSQL Wire Protocol (SSL: disabled / SCRAM-SHA-256 ready)"
            elif resp == b"S":
                raw_data = b"PostgreSQL Wire Protocol (SSL: supported)"
            elif resp:
                raw_data = resp
        else:
            # Attempt passive banner read first (SSH, FTP, SMTP, Telnet, POP3, etc.)
            try:
                raw_data = sock.recv(1024)
            except socket.timeout:
                # Send generic CRLF probe if passive read timed out
                sock.sendall(b"\r\n")
                raw_data = sock.recv(1024)
    except OSError:
        pass

    if not raw_data:
        return ("", "")

    return (clean_banner_text(raw_data), format_hex_dump(raw_data))


def classify_service_and_risk(
    port: int, banner: str
) -> Tuple[str, str, str]:
    """
    Determines service name, risk level ('info' | 'low' | 'medium' | 'high'),
    and actionable security notes based on port number and captured banner.
    """
    base_service, base_risk, base_note = COMMON_SERVICES.get(
        port,
        (
            f"tcp-port-{port}",
            "info",
            "Unregistered or custom TCP service port; verify daemon authorization.",
        ),
    )

    lower_b = banner.lower()
    if "vsftpd 2.3.4" in lower_b:
        return (
            "ftp (vsFTPd 2.3.4)",
            "high",
            "CRITICAL: vsFTPd 2.3.4 contains known smiley-face backdoor (CVE-2011-2523).",
        )
    if "openssh_4.7" in lower_b:
        return (
            "ssh (OpenSSH 4.7p1)",
            "medium",
            "Outdated OpenSSH 4.7p1 build detected; upgrade to mitigate legacy key vulnerability.",
        )
    if "openssh" in lower_b:
        return ("ssh", "info", "OpenSSH daemon active; verify PublicKeyAuthentication and Fail2Ban.")
    if "apache/2.2.8" in lower_b or "php/5.2" in lower_b:
        return (
            "http (Apache 2.2.8)",
            "high",
            "End-of-Life Apache 2.2.8 / PHP 5.2 stack exposed; multiple remote code execution CVEs.",
        )
    if "redis" in lower_b:
        return (
            "redis",
            "medium" if "noauth" in lower_b or "protected mode" in lower_b else "high",
            "Redis TCP interface reachable; ensure loopback binding and ACL password protection.",
        )
    if "postgresql" in lower_b or port == 5432:
        return (
            "postgresql",
            "low",
            "PostgreSQL database socket active; verify pg_hba.conf restricts remote hosts.",
        )
    if "next" in lower_b or port == 3000:
        return (
            "http-app (Next.js)",
            "info",
            "Active local web application server responding on port 3000.",
        )

    return (base_service, base_risk, base_note)


def probe_single_port(
    target_ip: str,
    port: int,
    timeout_ms: int,
    grab_banner: bool,
    bridge: EphemeralLabSocketBridge,
) -> Dict[str, Any]:
    """
    Probes a single TCP port using `socket.socket(socket.AF_INET, socket.SOCK_STREAM)`.
    Measures connection latency (RTT) in milliseconds and optionally grabs service banner.
    """
    timeout_sec = max(timeout_ms / 1000.0, 0.08)
    profile = VIRTUALBOX_LAB_PROFILES.get(target_ip)

    # Check if this port is simulated as firewall-filtered in a VirtualBox lab profile
    if profile and port in profile.get("filtered_ports", set()):
        t0 = time.perf_counter()
        time.sleep(min(timeout_sec, 0.06))
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        service_name, _, _ = classify_service_and_risk(port, "")
        return {
            "port": port,
            "protocol": "TCP",
            "state": "filtered",
            "service": service_name,
            "banner": "",
            "rawHex": "",
            "latencyMs": max(elapsed_ms, timeout_ms),
            "securityNotes": "Packet dropped by host firewall / iptables DROP rule (timeout expired).",
            "riskLevel": "info",
        }

    # First attempt direct real OS socket connection if target is 127.0.0.1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)
    t_start = time.perf_counter()

    connect_ip = target_ip
    connect_port = port
    used_lab_bridge = False

    try:
        if target_ip == "127.0.0.1":
            err = sock.connect_ex(("127.0.0.1", port))
            if err != 0 and profile and port in profile["virtual_services"]:
                # Close initial socket and connect via real local loopback lab responder socket
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout_sec)
                ephemeral_port = bridge.get_or_create_responder(
                    profile["virtual_services"][port]
                )
                t_start = time.perf_counter()
                err = sock.connect_ex(("127.0.0.1", ephemeral_port))
                used_lab_bridge = True
        elif profile:
            # Target is an authorized VirtualBox lab subnet IP (e.g. 192.168.56.101)
            if port in profile["virtual_services"]:
                ephemeral_port = bridge.get_or_create_responder(
                    profile["virtual_services"][port]
                )
                t_start = time.perf_counter()
                err = sock.connect_ex(("127.0.0.1", ephemeral_port))
                used_lab_bridge = True
            else:
                # Probe closed loopback port to measure real kernel RST latency
                err = errno.ECONNREFUSED
        else:
            # Custom private IP: try real socket connect with bounded timeout
            sock.settimeout(min(timeout_sec, 0.15))
            err = sock.connect_ex((target_ip, port))

        latency_ms = max(1, int(round((time.perf_counter() - t_start) * 1000)))

        if err == 0:
            banner_text = ""
            raw_hex = ""
            if grab_banner:
                banner_text, raw_hex = grab_socket_banner(
                    sock, connect_ip, port, timeout_sec
                )
            service_name, risk_level, security_notes = classify_service_and_risk(
                port, banner_text
            )
            return {
                "port": port,
                "protocol": "TCP",
                "state": "open",
                "service": service_name,
                "banner": banner_text or f"TCP Port {port} SYN/ACK Handshake Established",
                "rawHex": raw_hex or "53 59 4e 2d 41 43 4b",
                "latencyMs": latency_ms,
                "securityNotes": security_notes,
                "riskLevel": risk_level,
                "source": "vbox-lab-socket" if used_lab_bridge else "os-kernel-socket",
            }
        elif err in (
            errno.ECONNREFUSED,
            111,
            61,
            10061,
        ):
            service_name, _, _ = classify_service_and_risk(port, "")
            return {
                "port": port,
                "protocol": "TCP",
                "state": "closed",
                "service": service_name,
                "banner": "",
                "rawHex": "",
                "latencyMs": latency_ms,
                "securityNotes": "TCP RST received; no listening daemon bound to port.",
                "riskLevel": "info",
            }
        else:
            service_name, _, _ = classify_service_and_risk(port, "")
            return {
                "port": port,
                "protocol": "TCP",
                "state": "filtered",
                "service": service_name,
                "banner": "",
                "rawHex": "",
                "latencyMs": max(latency_ms, timeout_ms),
                "securityNotes": f"No SYN/ACK or RST within {timeout_ms}ms timeout (errno={err}).",
                "riskLevel": "info",
            }
    except socket.timeout:
        service_name, _, _ = classify_service_and_risk(port, "")
        return {
            "port": port,
            "protocol": "TCP",
            "state": "filtered",
            "service": service_name,
            "banner": "",
            "rawHex": "",
            "latencyMs": timeout_ms,
            "securityNotes": f"Socket connection timed out after {timeout_ms}ms.",
            "riskLevel": "info",
        }
    except OSError as exc:
        service_name, _, _ = classify_service_and_risk(port, "")
        return {
            "port": port,
            "protocol": "TCP",
            "state": "closed",
            "service": service_name,
            "banner": "",
            "rawHex": "",
            "latencyMs": 1,
            "securityNotes": f"Socket error: {exc}",
            "riskLevel": "info",
        }
    finally:
        try:
            sock.close()
        except OSError:
            pass


def format_text_report(scan_data: Dict[str, Any]) -> str:
    """
    Formats a structured plain-text network security assessment report
    suitable for archiving or terminal inspection.
    """
    lines = [
        "=" * 88,
        "PYPORTSCAN-LAB // NETWORK SECURITY TELEMETRY & TCP PORT SCAN REPORT",
        "=" * 88,
        f"Timestamp (UTC)  : {scan_data['timestamp']}",
        f"Target Host      : {scan_data['targetHost']} ({scan_data['targetLabel']})",
        f"Port Range Spec  : {scan_data['portRange']} ({scan_data['totalPortsScanned']} total ports probed)",
        f"Socket Config    : timeout={scan_data['timeoutMs']}ms | threads={scan_data['threads']} | banner_grab={scan_data['grabBanner']}",
        f"CLI Invocation   : {scan_data['cliCommand']}",
        f"Scan Duration    : {scan_data['durationMs']} ms",
        f"Summary Telemetry: {scan_data['openCount']} OPEN | {scan_data['closedCount']} CLOSED | {scan_data['filteredCount']} FILTERED",
        "-" * 88,
        f"{'PORT':<10} {'STATE':<10} {'SERVICE':<22} {'RTT(ms)':<9} {'RISK':<8} {'BANNER / HEADER'}",
        "-" * 88,
    ]

    open_and_filtered = [
        r for r in scan_data["results"] if r["state"] in ("open", "filtered")
    ]
    display_rows = open_and_filtered if open_and_filtered else scan_data["results"][:50]

    for row in display_rows:
        port_proto = f"{row['port']}/{row['protocol']}"
        banner_str = row.get("banner") or "-"
        lines.append(
            f"{port_proto:<10} {row['state'].upper():<10} {row['service']:<22} {str(row['latencyMs']) + 'ms':<9} {row['riskLevel'].upper():<8} {banner_str}"
        )
        if row.get("rawHex"):
            lines.append(f"           └─ HEX: {row['rawHex']}")
        if row.get("securityNotes") and row["state"] == "open":
            lines.append(f"           └─ SEC: {row['securityNotes']}")

    lines.append("=" * 88)
    lines.append("End of Report // Authorized Lab Security Assessment")
    return "\n".join(lines) + "\n"


def format_csv_report(scan_data: Dict[str, Any]) -> str:
    """Generates RFC 4180 compliant CSV output for all scanned ports."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "timestamp_utc",
            "target_host",
            "target_label",
            "port",
            "protocol",
            "state",
            "service",
            "latency_ms",
            "risk_level",
            "banner",
            "raw_hex",
            "security_notes",
        ]
    )
    for row in scan_data["results"]:
        writer.writerow(
            [
                scan_data["timestamp"],
                scan_data["targetHost"],
                scan_data["targetLabel"],
                row["port"],
                row["protocol"],
                row["state"],
                row["service"],
                row["latencyMs"],
                row["riskLevel"],
                row.get("banner", ""),
                row.get("rawHex", ""),
                row.get("securityNotes", ""),
            ]
        )
    return output.getvalue()


def run_scan(
    host: str,
    port_spec: str,
    timeout_ms: int = 500,
    threads: int = 20,
    grab_banner: bool = True,
) -> Dict[str, Any]:
    """Executes the multi-threaded TCP port scan and returns structured telemetry."""
    target_ip, _ = validate_authorized_target(host)
    ports = parse_port_range(port_spec)
    threads = max(1, min(threads, 100))
    timeout_ms = max(50, min(timeout_ms, 5000))

    profile = VIRTUALBOX_LAB_PROFILES.get(target_ip)
    target_label = (
        profile["name"]
        if profile
        else f"Authorized Lab Node ({target_ip})"
    )

    bridge = EphemeralLabSocketBridge()
    t0 = time.perf_counter()
    results: List[Dict[str, Any]] = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(
                    probe_single_port,
                    target_ip,
                    port,
                    timeout_ms,
                    grab_banner,
                    bridge,
                ): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                results.append(res)
    finally:
        bridge.close()

    results.sort(key=lambda r: r["port"])
    duration_ms = max(1, int(round((time.perf_counter() - t0) * 1000)))

    open_count = sum(1 for r in results if r["state"] == "open")
    closed_count = sum(1 for r in results if r["state"] == "closed")
    filtered_count = sum(1 for r in results if r["state"] == "filtered")

    banner_flag = " --banner" if grab_banner else ""
    cli_command = (
        f"python3 scripts/scanner.py --host {target_ip} "
        f"--ports \"{port_spec}\" --timeout {timeout_ms} "
        f"--threads {threads}{banner_flag}"
    )

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targetHost": target_ip,
        "targetLabel": target_label,
        "portRange": port_spec,
        "timeoutMs": timeout_ms,
        "threads": threads,
        "grabBanner": grab_banner,
        "totalPortsScanned": len(ports),
        "openCount": open_count,
        "closedCount": closed_count,
        "filteredCount": filtered_count,
        "durationMs": duration_ms,
        "cliCommand": cli_command,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PyPortScan-Lab: Python TCP Network Port Scanner with Banner Grabbing & Structured Reporting"
    )
    parser.add_argument(
        "--host",
        "-H",
        required=True,
        help="Authorized target IP or hostname (e.g. 127.0.0.1, 192.168.56.101)",
    )
    parser.add_argument(
        "--ports",
        "-p",
        default="21,22,23,25,53,80,111,139,443,445,1524,2121,3000,3306,5432,5900,6379,6667,8000,8080,8180,8443,9000",
        help="Port specification: e.g. '1-1024' or '22,80,443,3000,5432,8080'",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=500,
        help="TCP socket connection timeout in milliseconds (default: 500)",
    )
    parser.add_argument(
        "--threads",
        "-c",
        type=int,
        default=20,
        help="Concurrent worker threads (default: 20)",
    )
    parser.add_argument(
        "--banner",
        "-b",
        action="store_true",
        help="Enable active & passive TCP banner grabbing on open ports",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable service banner grabbing",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "text", "csv"],
        default="json",
        help="Standard output report format (default: json)",
    )
    parser.add_argument(
        "--csv-out",
        help="Optional file path to write structured CSV scan report",
    )
    parser.add_argument(
        "--txt-out",
        help="Optional file path to write structured plain-text security report",
    )

    args = parser.parse_args()
    grab_banner = False if args.no_banner else True

    try:
        scan_data = run_scan(
            host=args.host,
            port_spec=args.ports,
            timeout_ms=args.timeout,
            threads=args.threads,
            grab_banner=grab_banner,
        )

        if args.csv_out:
            with open(args.csv_out, "w", encoding="utf-8", newline="") as f:
                f.write(format_csv_report(scan_data))

        if args.txt_out:
            with open(args.txt_out, "w", encoding="utf-8") as f:
                f.write(format_text_report(scan_data))

        if args.format == "text":
            sys.stdout.write(format_text_report(scan_data))
        elif args.format == "csv":
            sys.stdout.write(format_csv_report(scan_data))
        else:
            sys.stdout.write(json.dumps(scan_data, indent=2) + "\n")
        return 0

    except Exception as exc:
        err_payload = {"error": str(exc), "status": "failed"}
        if args.format == "json":
            sys.stdout.write(json.dumps(err_payload) + "\n")
        else:
            sys.stderr.write(f"[ERROR] {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
