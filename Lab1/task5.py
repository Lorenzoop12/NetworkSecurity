import argparse
import os
import re
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ONION_BACKEND = ("127.0.0.1", 8081)
VPN_ADDRESS = ("0.0.0.0", 8090)

BASE = os.path.dirname(os.path.abspath(__file__))
TOR_DIR = os.path.join(BASE, "tor_data")
HS_DIR = os.path.join(TOR_DIR, "hidden_service")
AUTH_DIR = os.path.join(HS_DIR, "authorized_clients")
TORRC = os.path.join(BASE, "torrc")

_lock = threading.Lock()
_last_token = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

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
        return self.rfile.read(length)

    def dispatch(self):
        body = self.read_body()
        path = self.path.split("?", 1)[0]
        self.route(self.command, path, body)

    def route(self, method, path, body):
        self.reply(404, b"not found")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = dispatch


class OnionHandler(Handler):
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
                _last_token = body
            return self.reply(200, b"OK")
        self.reply(404, b"not found")


class VPNHandler(Handler):
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


def tor_path(p):
    return '"' + p.replace("\\", "/") + '"'


def setup(auth_file):
    if not os.path.isfile(auth_file):
        sys.exit(f"File not found: {auth_file}")
    with open(auth_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()
    if not re.fullmatch(r"descriptor:x25519:[A-Z2-7]{52}", content):
        sys.exit("Invalid netsec.auth format")

    os.makedirs(AUTH_DIR, exist_ok=True)
    name = os.path.basename(auth_file)
    if not name.endswith(".auth"):
        name += ".auth"
    shutil.copyfile(auth_file, os.path.join(AUTH_DIR, name))
    for d in (TOR_DIR, HS_DIR, AUTH_DIR):
        os.chmod(d, 0o700)

    with open(TORRC, "w", encoding="utf-8") as f:
        f.write(
            f"DataDirectory {tor_path(os.path.join(TOR_DIR, 'data'))}\n"
            f"HiddenServiceDir {tor_path(HS_DIR)}\n"
            "HiddenServiceVersion 3\n"
            f"HiddenServicePort 80 {ONION_BACKEND[0]}:{ONION_BACKEND[1]}\n"
            "SocksPort 0\n"
            "Log notice stdout\n"
        )

def onion_address():
    try:
        with open(os.path.join(HS_DIR, "hostname"), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--setup", metavar="NETSEC_AUTH")
    args = ap.parse_args()
    if args.setup:
        return setup(args.setup)

    vpn = ThreadingHTTPServer(VPN_ADDRESS, VPNHandler)
    threading.Thread(target=vpn.serve_forever, daemon=True).start()

    addr = onion_address()
    print(f"Onion address: {addr}" if addr else
          "Onion address not available yet: start Tor first")
    ThreadingHTTPServer(ONION_BACKEND, OnionHandler).serve_forever()


if __name__ == "__main__":
    main()