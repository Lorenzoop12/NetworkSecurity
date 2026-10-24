import asyncio
import datetime
import hashlib
import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hypercorn.asyncio import serve
from hypercorn.config import Config

HOSTNAME = "server.netsec.lab"
PORT = 4433
BASE = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE, "server.crt")
KEY_FILE = os.path.join(BASE, "server.key")

PROTOCOL_NAMES = {"1.0": "HTTP/1.0", "1.1": "HTTP/1.1", "2": "HTTP/2", "3": "HTTP/3"}


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
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            digest.update(message.get("body", b""))
            if not message.get("more_body", False):
                break
        return await respond(send, 200, digest.hexdigest().encode())

    await respond(send, 404, b"not found")

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
    if os.name == "nt":
        return [f"0.0.0.0:{PORT}", f"[::]:{PORT}"]
    return [f"[::]:{PORT}"]


def main():
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        generate_certificate()

    config = Config()
    config.certfile = CERT_FILE
    config.keyfile = KEY_FILE
    config.bind = addresses()
    config.quic_bind = addresses()
    config.alt_svc_headers = [f'h3=":{PORT}"']
    asyncio.run(serve(app, config))


if __name__ == "__main__":
    main()