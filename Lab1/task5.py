#!/usr/bin/env python3
"""Onion hidden service backend + VPN claim endpoint, with shared state.

Two listeners in ONE process, so they share the last claim token:

  127.0.0.1:8081   behind the Tor v3 onion service (Tor forwards onion port 80 here)
      GET  /        -> 200
      POST /claim   -> 200, stores the (plain text) request body as the token
  0.0.0.0:8090     reachable on your VPN address
      GET  /claim   -> the last token received, as plain text

Usage
  1) python onion_server.py --setup path\\to\\netsec.auth   (once: builds the Tor folder + torrc)
  2) tor -f torrc                                           (leave it running)
  3) python onion_server.py                                 (leave it running)
The onion address is the content of  tor_data/hidden_service/hostname
"""
import argparse
import os
import re
import shutil
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ONION_BACKEND = ("127.0.0.1", 8081)  # loopback ONLY: the only way in must be through Tor
VPN_ADDRESS = ("0.0.0.0", 8090)
MAX_BODY = 1 << 16

BASE = os.path.dirname(os.path.abspath(__file__))
TOR_DIR = os.path.join(BASE, "tor_data")
HS_DIR = os.path.join(TOR_DIR, "hidden_service")
AUTH_DIR = os.path.join(HS_DIR, "authorized_clients")
TORRC = os.path.join(BASE, "torrc")

# State shared by both listeners
_lock = threading.Lock()
_last_token: bytes | None = None


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OnionLab/1.0"
    timeout = 30

    def log_message(self, fmt, *args):
        print(f"[:{self.server.server_address[1]}] {self.address_string()} {fmt % args}")

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def read_body(self):
        try:
            length = max(0, int(self.headers.get("Content-Length") or 0))
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self.close_connection = True
            return None
        return self.rfile.read(length) if length else b""

    def dispatch(self):
        body = self.read_body()  # always consume it, keeps keep-alive in sync
        if body is None:
            return self.reply(413, b"body too large")
        path = self.path.split("?", 1)[0]
        self.route(self.command, path, body)

    def route(self, method, path, body):
        self.reply(404, b"not found")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = dispatch


class OnionHandler(Handler):
    """What the world sees through the onion service."""

    def route(self, method, path, body):
        global _last_token
        if path == "/":
            if method != "GET":
                return self.reply(405, b"method not allowed", {"Allow": "GET"})
            return self.reply(200, b"Hello from the onion service\n")
        if path == "/claim":
            if method != "POST":
                return self.reply(405, b"method not allowed", {"Allow": "POST"})
            if not body:
                return self.reply(400, b"empty token")
            with _lock:
                _last_token = body  # stored exactly as received
            return self.reply(200, b"OK")
        self.reply(404, b"not found")


class VPNHandler(Handler):
    """What the checker reads on <VPN IP>:8090."""

    def route(self, method, path, body):
        if path != "/claim":
            return self.reply(404, b"not found")
        if method != "GET":
            return self.reply(405, b"method not allowed", {"Allow": "GET"})
        with _lock:
            token = _last_token
        if token is None:
            return self.reply(404, b"no token received yet")
        self.reply(200, token)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":  # never silently share a port with another program
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


# --------------------------------------------------------------------------
# Tor preparation
# --------------------------------------------------------------------------
def tor_path(p):
    return '"' + p.replace("\\", "/") + '"'  # forward slashes + quotes work on Windows too


def setup(auth_file):
    if not os.path.isfile(auth_file):
        sys.exit(f"File not found: {auth_file}")
    with open(auth_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()
    if not re.fullmatch(
            r"descriptor:x25519:[A-Z2-7]{52}",
            content
    ):
        sys.exit(
            "Invalid netsec.auth format. Expected exactly one line:\n"
            "descriptor:x25519:<52 Base32 characters>"
        )

    os.makedirs(AUTH_DIR, exist_ok=True)
    name = os.path.basename(auth_file)
    if not name.endswith(".auth"):
        name += ".auth"  # Tor only reads files ending in .auth
    shutil.copyfile(auth_file, os.path.join(AUTH_DIR, name))
    if os.name != "nt":  # Tor insists on private directories
        for d in (TOR_DIR, HS_DIR, AUTH_DIR):
            os.chmod(d, 0o700)

    with open(TORRC, "w", encoding="utf-8") as f:
        f.write(
            "# generated by onion_server.py --setup\n"
            f"DataDirectory {tor_path(os.path.join(TOR_DIR, 'data'))}\n"
            f"HiddenServiceDir {tor_path(HS_DIR)}\n"
            "HiddenServiceVersion 3\n"
            f"HiddenServicePort 80 {ONION_BACKEND[0]}:{ONION_BACKEND[1]}\n"
            "SocksPort 0\n"  # we only host a service: no SOCKS port, no clash with Tor Browser
            "Log notice stdout\n"
        )
    print(f"Client authorization installed: {os.path.join(AUTH_DIR, name)}")
    print(f"Tor configuration written:      {TORRC}")
    print("\nNext: run   tor -f \"" + TORRC + "\"   and wait until the log says 'Bootstrapped 100%'.\n"
          "The onion address will then be in: " + os.path.join(HS_DIR, "hostname"))


def onion_address():
    try:
        with open(os.path.join(HS_DIR, "hostname"), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setup", metavar="NETSEC_AUTH",
                    help="prepare the Tor folder and torrc using the course netsec.auth file, then exit")
    args = ap.parse_args()
    if args.setup:
        return setup(args.setup)

    onion = Server(ONION_BACKEND, OnionHandler)
    vpn = Server(VPN_ADDRESS, VPNHandler)
    for s in (onion, vpn):
        threading.Thread(target=s.serve_forever, daemon=True).start()

    print(f"Onion backend (Tor -> here) on {ONION_BACKEND[0]}:{ONION_BACKEND[1]}")
    print(f"VPN claim endpoint          on port {VPN_ADDRESS[1]}  (GET /claim)")
    addr = onion_address()
    print(f"Onion address: {addr}" if addr else
          "Onion address: not available yet (start Tor first; see the docstring).")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()