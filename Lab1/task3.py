import datetime
import hmac
import json
import os
import secrets
import socket
import ssl
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOSTNAME = "server.netsec.lab"
TLS_PORT, MTLS_PORT = 8443, 8444
PASSWORD = "netsec"
COOKIE_NAME = "session"

BASE = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE, "server.crt")
KEY_FILE = os.path.join(BASE, "server.key")
CA_FILE = os.path.join(BASE, "ca.crt")

sessions: dict[str, str] = {}
sessions_lock = threading.Lock()


def generate_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, key_cert_sign=True,
            content_commitment=False, data_encipherment=False, key_agreement=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def make_context(require_client_cert: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=CA_FILE)
    return ctx


class TLSServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def __init__(self, port, handler, ctx):
        self.ssl_context = ctx
        super().__init__(("::", port), handler)

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class TLSHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request = self.server.ssl_context.wrap_socket(self.request, server_side=True)
        super().setup()

    def reply(self, status, body=b"", ctype="text/plain; charset=utf-8", headers=None):
        self.send_response(status)
        if body:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def reply_json(self, status, payload, headers=None):
        self.reply(status, json.dumps(payload).encode(), "application/json", headers)

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(max(length, 0))

    def not_allowed(self, allow):
        self.reply_json(405, {"error": "method not allowed"}, {"Allow": allow})

    def route(self, path, body):
        self.reply_json(404, {"error": "not found"})

    def dispatch(self):
        body = self.read_body()
        self.route(urlsplit(self.path).path, body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = dispatch


class WebHandler(TLSHandler):
    def route(self, path, body):
        m = self.command
        if path == "/":
            return self.reply(200, b"Hello from server.netsec.lab\n") if m == "GET" else self.not_allowed("GET")
        if path == "/login":
            return self.login(body) if m == "POST" else self.not_allowed("POST")
        if path == "/me":
            return self.me() if m == "GET" else self.not_allowed("GET")
        self.reply_json(404, {"error": "not found"})

    def login(self, body):
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self.reply_json(400, {"error": "malformed JSON"})
        user = data.get("user") if isinstance(data, dict) else None
        if not isinstance(user, str) or not user:
            return self.reply_json(400, {"error": '"user" must be a non-empty string'})
        password = data.get("password")
        if not isinstance(password, str) or not hmac.compare_digest(
                password.encode("utf-8"), PASSWORD.encode("utf-8")):
            return self.reply_json(401, {"error": "invalid credentials"})
        token = secrets.token_urlsafe(32)
        with sessions_lock:
            sessions[token] = user
        cookie = f"{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict"
        self.reply_json(200, {"user": user}, {"Set-Cookie": cookie})

    def me(self):
        user = None
        raw = self.headers.get("Cookie")
        if raw:
            try:
                morsel = SimpleCookie(raw).get(COOKIE_NAME)
            except Exception:
                morsel = None
            if morsel:
                with sessions_lock:
                    user = sessions.get(morsel.value)
        if user is None:
            return self.reply_json(401, {"error": "not authenticated"})
        self.reply_json(200, {"user": user})


class MTLSHandler(TLSHandler):
    def route(self, path, body):
        if path != "/whoami":
            return self.reply_json(404, {"error": "not found"})
        if self.command != "GET":
            return self.not_allowed("GET")
        cert = self.request.getpeercert() or {}
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return self.reply(200, value.encode("utf-8"))
        self.reply(403, b"client certificate has no CN")


def main():
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        generate_certificate()
    mtls = TLSServer(MTLS_PORT, MTLSHandler, make_context(True))
    threading.Thread(target=mtls.serve_forever, daemon=True).start()
    TLSServer(TLS_PORT, WebHandler, make_context(False)).serve_forever()


if __name__ == "__main__":
    main()