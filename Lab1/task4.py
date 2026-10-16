import asyncio
import datetime
import hashlib
import ipaddress
import os
import socket
import sys

try:
    from hypercorn.asyncio import serve
    from hypercorn.config import Config
    import aioquic
except ImportError:
    sys.exit('Missing packages. Install them with:  pip install "hypercorn[h3]"')

HOSTNAME = "server.netsec.lab"
PORT = 4433
BASE = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE, "server.crt")
KEY_FILE = os.path.join(BASE, "server.key")

PROTOCOL_NAMES = {"1.0": "HTTP/1.0", "1.1": "HTTP/1.1", "2": "HTTP/2", "3": "HTTP/3"}


# --------------------------------------------------------------------------
# Self-signed certificate (same logic as the HTTPS task; reuses server.crt if valid)
# --------------------------------------------------------------------------
def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def certificate_is_usable() -> bool:
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        return False
    try:
        from cryptography import x509
        with open(CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        now = _now()
        return (
            cert.not_valid_before_utc <= now
            and cert.not_valid_after_utc > now + datetime.timedelta(days=7)
            and HOSTNAME in san.value.get_values_for_type(x509.DNSName)
        )
    except Exception:
        return False


def generate_certificate():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))  # tolerate clock skew
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(HOSTNAME),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
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
    print(f"Created {CERT_FILE} (valid 365 days, SAN DNS: {HOSTNAME})")


# --------------------------------------------------------------------------
# The application (ASGI): identical for HTTP/1.1, HTTP/2 and HTTP/3
# --------------------------------------------------------------------------
async def respond(send, status, body=b"", ctype="text/plain; charset=utf-8", extra=()):
    headers = [(b"content-length", str(len(body)).encode())]
    if body:
        headers.append((b"content-type", ctype.encode()))
    headers.extend(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return

    method, path = scope["method"], scope["path"]

    if path == "/":
        if method != "GET":
            return await respond(send, 405, b"method not allowed", extra=[(b"allow", b"GET")])
        return await respond(send, 200, b"Hello from server.netsec.lab\n")

    if path == "/proto":
        if method != "GET":
            return await respond(send, 405, b"method not allowed", extra=[(b"allow", b"GET")])
        version = scope.get("http_version", "")
        return await respond(send, 200, PROTOCOL_NAMES.get(version, f"HTTP/{version}").encode())

    if path == "/hash":
        if method != "POST":
            return await respond(send, 405, b"method not allowed", extra=[(b"allow", b"POST")])
        digest = hashlib.sha256()
        while True:  # hash chunk by chunk: many parallel 256 KB bodies cost no extra memory
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            digest.update(message.get("body", b""))
            if not message.get("more_body", False):
                break
        return await respond(send, 200, digest.hexdigest().encode())

    await respond(send, 404, b"not found")


# --------------------------------------------------------------------------
def ipv6_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::", 0))
        return True
    except OSError:
        return False


def addresses():
    if not ipv6_available():
        return [f"0.0.0.0:{PORT}"]
    if os.name == "nt":  # Windows sockets are IPv6-only by default: bind both
        return [f"0.0.0.0:{PORT}", f"[::]:{PORT}"]
    return [f"[::]:{PORT}"]  # elsewhere one dual-stack socket serves both


def main():
    if not certificate_is_usable():
        generate_certificate()

    config = Config()
    config.certfile = CERT_FILE
    config.keyfile = KEY_FILE
    config.bind = addresses()          # TCP: HTTP/1.1 + HTTP/2 (ALPN)
    config.quic_bind = addresses()     # UDP: HTTP/3 (ALPN h3)
    config.alt_svc_headers = [f'h3=":{PORT}"']  # advertised on every response
    config.accesslog = "-"
    config.errorlog = "-"

    print(f"HTTPS (h2/http1.1) on TCP {PORT}, HTTP/3 on UDP {PORT}")
    try:
        asyncio.run(serve(app, config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()