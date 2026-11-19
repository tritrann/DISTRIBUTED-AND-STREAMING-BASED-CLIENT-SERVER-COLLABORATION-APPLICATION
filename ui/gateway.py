import argparse
import base64
import json
import mimetypes
import os
import secrets
import socket
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  
from client.client import ChatClient 

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 64 * 1024 * 1024       
SESSION_IDLE = 60                  

REASONS = {200: "OK", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
           405: "Method Not Allowed", 413: "Payload Too Large", 500: "Internal Server Error"}


class Session:
    def __init__(self):
        self.token = secrets.token_hex(16)
        self.lock = threading.Lock()
        self.events = []
        self.next_seq = 1
        self.last_poll = time.time()
        self.client = ChatClient(on_event=self.add_event)

    def add_event(self, event):
        with self.lock:
            event = dict(event)
            event["seq"] = self.next_seq
            self.next_seq += 1
            self.events.append(event)
            if len(self.events) > 5000:
                self.events = self.events[-2000:]

    def events_after(self, seq):
        with self.lock:
            return [e for e in self.events if e["seq"] > seq]


sessions = {}
sessions_lock = threading.Lock()



def read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk or len(data) > 64 * 1024:
            return None
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    method, target, _version = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0") or 0)
    if length > MAX_BODY:
        raise ValueError("too large")
    while len(body) < length:
        chunk = conn.recv(min(1 << 20, length - len(body)))
        if not chunk:
            return None
        body += chunk
    url = urllib.parse.urlsplit(target)
    query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
    return method, url.path, query, headers, body


def send_response(conn, status, body=b"", content_type="application/json", extra=None):
    head = [f"HTTP/1.1 {status} {REASONS.get(status, '')}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Cache-Control: no-store",
            "Connection: close"]
    for key, value in (extra or {}).items():
        head.append(f"{key}: {value}")
    conn.sendall(("\r\n".join(head) + "\r\n\r\n").encode("utf-8") + body)


def json_body(obj):
    return json.dumps(obj).encode("utf-8")

def get_session(headers, query):
    token = headers.get("x-token") or query.get("token", "")
    with sessions_lock:
        session = sessions.get(token)
    if session is not None:
        session.last_poll = time.time()
    return session

def route(method, path, query, headers, body):
    if path == "/favicon.ico":
        return 204, b"", "image/x-icon", None
    if method == "GET" and (path == "/" or path.startswith("/static/")):
        name = "index.html" if path == "/" else os.path.basename(path)
        file_path = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(file_path):
            return 404, b"not found", "text/plain", None
        with open(file_path, "rb") as f:
            content = f.read()
        ctype = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return 200, content, ctype, None

    if not path.startswith("/api/"):
        return 404, json_body({"error": "not found"}), "application/json", None

    data = {}
    if method == "POST" and body:
        try:
            data = json.loads(body.decode("utf-8"))
        except ValueError:
            return 400, json_body({"error": "invalid JSON"}), "application/json", None

    if path == "/api/login" and method == "POST":
        return api_login(data)

    session = get_session(headers, query)
    if session is None:
        return 401, json_body({"error": "not logged in"}), "application/json", None
    client = session.client

    if path == "/api/poll" and method == "GET":
        since = int(query.get("since", "0") or 0)
        return 200, json_body({
            "events": session.events_after(since),
            "users": client.users, "peers": client.peers,
            "connected": client.connected, "username": client.username,
            "server": f"{client.server[0]}:{client.server[1]}" if client.server else "",
            "stats": client.stats,
        }), "application/json", None

    if path == "/api/send" and method == "POST":
        to, text = data.get("to", "*"), data.get("text", "")
        if not text:
            return 400, json_body({"error": "empty message"}), "application/json", None
        try:
            client.send_text(to, text)
        except OSError as err:
            return 200, json_body({"ok": False, "error": str(err)}), "application/json", None
        return 200, json_body({"ok": True}), "application/json", None

    if path == "/api/file" and method == "POST":
        to, name = data.get("to", ""), data.get("name", "file")
        if not to or to == "*":
            return 400, json_body({"error": "choose one user to send the file to"}), "application/json", None
        try:
            content = base64.b64decode(data.get("data", ""))
        except ValueError:
            return 400, json_body({"error": "bad file data"}), "application/json", None
        file_id = client.send_file(to, name, content)
        return 200, json_body({"ok": True, "file_id": file_id}), "application/json", None

    if path == "/api/download" and method == "GET":
        file_path = client.files.get(query.get("id", ""))
        if not file_path or not os.path.isfile(file_path):
            return 404, json_body({"error": "no such file"}), "application/json", None
        with open(file_path, "rb") as f:
            content = f.read()
        name = urllib.parse.quote(os.path.basename(file_path))
        return 200, content, "application/octet-stream", {
            "Content-Disposition": f"attachment; filename*=UTF-8''{name}"}

    if path == "/api/logout" and method == "POST":
        with sessions_lock:
            sessions.pop(session.token, None)
        client.close()
        return 200, json_body({"ok": True}), "application/json", None

    return 405, json_body({"error": "method not allowed"}), "application/json", None


def api_login(data):
    host = data.get("host") or "127.0.0.1"
    try:
        port = int(data.get("port") or config.SERVER_TCP_PORT)
    except ValueError:
        return 400, json_body({"error": "bad port"}), "application/json", None
    session = Session()
    try:
        session.client.connect(host, port)
    except OSError as err:
        return 200, json_body({"ok": False, "error": f"cannot reach {host}:{port} ({err})"}), "application/json", None
    ok, reason = session.client.login(data.get("username", ""), data.get("password", ""))
    if not ok:
        session.client.close()
        return 200, json_body({"ok": False, "error": reason}), "application/json", None
    with sessions_lock:
        sessions[session.token] = session
    return 200, json_body({"ok": True, "token": session.token,
                           "username": session.client.username}), "application/json", None

def handle_connection(conn, addr):
    try:
        conn.settimeout(30)
        request = read_request(conn)
        if request is None:
            return
        status, body, ctype, extra = route(*request)
        send_response(conn, status, body, ctype, extra)
    except ValueError:
        try:
            send_response(conn, 413, json_body({"error": "request too large"}))
        except OSError:
            pass
    except Exception as err:         
        print(f"[gateway] error for {addr}: {err}")
        try:
            send_response(conn, 500, json_body({"error": "internal error"}))
        except OSError:
            pass
    finally:
        conn.close()


def reap_idle_sessions():
    while True:
        time.sleep(10)
        now = time.time()
        with sessions_lock:
            idle = [s for s in sessions.values() if now - s.last_poll > SESSION_IDLE]
            for s in idle:
                sessions.pop(s.token, None)
        for s in idle:
            s.client.close()


def serve(host, port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    threading.Thread(target=reap_idle_sessions, daemon=True).start()
    shown = "127.0.0.1" if host == "0.0.0.0" else host
    print(f"[gateway] running, open http://{shown}:{port}/ in your browser (Ctrl+C to stop)", flush=True)
    try:
        while True:
            conn, addr = listener.accept()
            threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
        with sessions_lock:
            for s in sessions.values():
                s.client.close()


def main():
    parser = argparse.ArgumentParser(description="HTTP gateway for the web UI")
    parser.add_argument("--host", default=config.GATEWAY_HOST)
    parser.add_argument("--port", type=int, default=config.GATEWAY_PORT)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
