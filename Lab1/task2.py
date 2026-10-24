import json
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORT = 8080

notes: dict[int, str] = {}
next_id = 1
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, status, payload=None, extra=None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if status != 204:
            if payload is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def error(self, status, message, extra=None):
        self.send_json(status, {"error": message}, extra)

    def method_not_allowed(self, allow):
        self.error(405, "method not allowed", {"Allow": allow})

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(max(length, 0))

    def dispatch(self):
        body = self.read_body()
        parts = urlsplit(self.path)
        path, method = parts.path, self.command

        if path == "/":
            if method != "GET":
                return self.method_not_allowed("GET")
            return self.send_json(200, {"status": "ok"})

        if path == "/echo":
            if method != "GET":
                return self.method_not_allowed("GET")
            q = parse_qs(parts.query, keep_blank_values=True)
            if "msg" not in q:
                return self.error(400, "missing msg parameter")
            return self.send_json(200, {"msg": q["msg"][0]})

        if path == "/notes":
            if method != "POST":
                return self.method_not_allowed("POST")
            return self.create_note(body)

        if path.startswith("/notes/") and "/" not in path[len("/notes/"):]:
            if method not in ("GET", "DELETE"):
                return self.method_not_allowed("GET, DELETE")
            return self.note_by_id(method, path[len("/notes/"):])

        return self.error(404, "not found")

    def create_note(self, body):
        global next_id
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return self.error(415, "Content-Type must be application/json")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self.error(400, "malformed JSON")
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            return self.error(400, '"text" must be a string')
        with lock:
            note_id = next_id
            next_id += 1
            notes[note_id] = data["text"]
        self.send_json(201, {"id": note_id})

    def note_by_id(self, method, id_str):
        if not re.fullmatch(r"[0-9]{1,18}", id_str):
            return self.error(404, "not found")
        note_id = int(id_str)
        with lock:
            if method == "GET":
                text = notes.get(note_id)
                found = text is not None
            else:
                found = notes.pop(note_id, None) is not None
        if not found:
            return self.error(404, "not found")
        if method == "GET":
            return self.send_json(200, {"id": note_id, "text": text})
        self.send_json(204)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = dispatch


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    Server(("::", PORT), Handler).serve_forever()