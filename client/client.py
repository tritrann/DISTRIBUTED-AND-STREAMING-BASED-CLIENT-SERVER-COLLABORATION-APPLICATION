
import base64
import hashlib
import os
import secrets
import socket
import threading
import time

import config
from common.crypto import decode_message, encode_message
from common.framing import pack, split


class ChatClient:
    def __init__(self, on_event=None, download_dir=None):
        self.on_event = on_event or (lambda event: None)
        self.download_dir = download_dir or config.DOWNLOAD_DIR
        self.sock = None
        self.connected = False
        self.username = None
        self.server = None
        self.users = []
        self.peers = []
        self.send_lock = threading.Lock()     
        self.login_done = threading.Event()
        self.login_result = (False, "no answer")
        self.incoming = {}                     
        self.files = {}                        
        self.stats = {"sent": 0, "received": 0, "bytes_sent": 0, "bytes_received": 0}

    def connect(self, host, port, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(None)
        self.server = (host, port)
        self.connected = True
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._heartbeat, daemon=True).start()
        self._send({"type": "HELLO"})
        self._emit({"type": "status", "text": f"connected to {host}:{port}"})

    def login(self, username, password, timeout=10.0):
        self.login_done.clear()
        self._send({"type": "LOGIN", "username": username, "password": password})
        if not self.login_done.wait(timeout):
            return False, "no answer from server"
        ok, reason = self.login_result
        if ok:
            self.username = username
        return ok, reason

    def close(self):
        if not self.connected:
            return
        try:
            self._send({"type": "BYE"})
        except OSError:
            pass
        self._disconnect("closed by user")

    def _disconnect(self, reason):
        if not self.connected:
            return
        self.connected = False
        try:
            self.sock.close()
        except OSError:
            pass
        self._emit({"type": "disconnected", "reason": reason})

    def _send(self, message):
        if not self.connected:
            raise OSError("not connected")
        frame = pack(encode_message(message))
        with self.send_lock:
            try:
                self.sock.sendall(frame)
            except OSError as err:
                self._disconnect(f"send failed: {err}")
                raise
        self.stats["sent"] += 1
        self.stats["bytes_sent"] += len(frame)

    def send_text(self, to, text):
        self._send({"type": "MSG", "to": to, "text": text})

    def request_users(self):
        self._send({"type": "USER_LIST"})

    def send_file(self, to, name, data, wait=False):
        file_id = secrets.token_hex(8)
        thread = threading.Thread(target=self._send_file, args=(to, name, data, file_id), daemon=True)
        thread.start()
        if wait:
            thread.join()
        return file_id

    def send_file_path(self, to, path, wait=False):
        with open(path, "rb") as f:
            data = f.read()
        return self.send_file(to, os.path.basename(path), data, wait=wait)

    def _send_file(self, to, name, data, file_id):
        size = len(data)
        chunk_size = config.FILE_CHUNK_SIZE
        chunks = (size + chunk_size - 1) // chunk_size
        self._emit({"type": "file_start", "file_id": file_id, "direction": "send",
                    "peer": to, "name": name, "size": size})
        try:
            self._send({"type": "FILE_META", "to": to, "file_id": file_id, "name": name,
                        "size": size, "chunks": chunks,
                        "sha256": hashlib.sha256(data).hexdigest()})
            for index in range(chunks):
                part = data[index * chunk_size:(index + 1) * chunk_size]
                self._send({"type": "FILE_CHUNK", "to": to, "file_id": file_id, "index": index,
                            "data": base64.b64encode(part).decode("ascii")})
                self._emit({"type": "file_progress", "file_id": file_id, "direction": "send",
                            "done": min(size, (index + 1) * chunk_size), "size": size})
            self._send({"type": "FILE_END", "to": to, "file_id": file_id})
            self._emit({"type": "file_done", "file_id": file_id, "direction": "send",
                        "ok": True, "path": "", "reason": ""})
        except OSError as err:
            self._emit({"type": "file_done", "file_id": file_id, "direction": "send",
                        "ok": False, "path": "", "reason": str(err)})

    def _reader(self):
        buffer = b""
        while self.connected:
            try:
                chunk = self.sock.recv(65536)
            except OSError as err:
                self._disconnect(f"connection lost: {err}")
                return
            if not chunk:
                self._disconnect("server closed the connection")
                return
            buffer += chunk
            try:
                frames, buffer = split(buffer)
            except ValueError as err:
                self._disconnect(f"bad frame: {err}")
                return
            for frame in frames:
                self.stats["received"] += 1
                self.stats["bytes_received"] += len(frame) + 4
                try:
                    message = decode_message(frame)
                except ValueError:
                    self._emit({"type": "error", "reason": "cannot decrypt a message from the server"})
                    continue
                try:
                    self._handle(message)
                except Exception as err:      
                    self._emit({"type": "error", "reason": f"bad message: {err}"})

    def _handle(self, m):
        kind = m.get("type")
        if kind == "HELLO_ACK":
            self._emit({"type": "status", "text": f"handshake ok (conn #{m.get('conn_id')})"})
        elif kind == "LOGIN_OK":
            self.login_result = (True, "")
            self.login_done.set()
        elif kind == "LOGIN_FAIL":
            self.login_result = (False, m.get("reason", "login failed"))
            self.login_done.set()
        elif kind == "USER_LIST":
            self.users = m.get("users", [])
            self.peers = m.get("peers", [])
            self._emit({"type": "users", "users": self.users, "peers": self.peers})
        elif kind == "JOIN":
            if m["username"] not in self.users:
                self.users = sorted(self.users + [m["username"]])
            self._emit({"type": "join", "username": m["username"]})
            self.request_users()         
        elif kind == "LEAVE":
            self.users = [u for u in self.users if u != m["username"]]
            self.peers = [p for p in self.peers if p["username"] != m["username"]]
            self._emit({"type": "leave", "username": m["username"]})
        elif kind == "MSG":
            self._emit({"type": "message", "from": m.get("from"), "to": m.get("to"),
                        "text": m.get("text", ""), "ts": m.get("ts", time.time())})
        elif kind == "MSG_ACK":
            self._emit({"type": "sent", "to": m.get("to"), "ts": m.get("ts")})
        elif kind == "ERROR":
            self._emit({"type": "error", "reason": m.get("reason", "")})
        elif kind == "FILE_META":
            self._on_file_meta(m)
        elif kind == "FILE_CHUNK":
            self._on_file_chunk(m)
        elif kind == "FILE_END":
            self._on_file_end(m)

    def _on_file_meta(self, m):
        file_id = m["file_id"]
        self.incoming[file_id] = {"name": os.path.basename(m.get("name", "file")) or "file",
                                  "size": int(m.get("size", 0)), "chunks": int(m.get("chunks", 0)),
                                  "sha256": m.get("sha256", ""), "parts": {}, "done": 0,
                                  "from": m.get("from")}
        self._emit({"type": "file_start", "file_id": file_id, "direction": "receive",
                    "peer": m.get("from"), "name": self.incoming[file_id]["name"],
                    "size": self.incoming[file_id]["size"]})

    def _on_file_chunk(self, m):
        f = self.incoming.get(m.get("file_id"))
        if f is None:
            return
        index = int(m["index"])
        if index not in f["parts"]:
            part = base64.b64decode(m["data"])
            f["parts"][index] = part
            f["done"] += len(part)
        self._emit({"type": "file_progress", "file_id": m["file_id"], "direction": "receive",
                    "done": f["done"], "size": f["size"]})

    def _on_file_end(self, m):
        file_id = m.get("file_id")
        f = self.incoming.pop(file_id, None)
        if f is None:
            return
        missing = [i for i in range(f["chunks"]) if i not in f["parts"]]
        data = b"".join(f["parts"][i] for i in sorted(f["parts"]))
        if missing:
            reason = f"missing {len(missing)} chunk(s)"
        elif hashlib.sha256(data).hexdigest() != f["sha256"]:
            reason = "SHA-256 does not match (file corrupted)"
        else:
            reason = ""
        if reason:
            self._emit({"type": "file_done", "file_id": file_id, "direction": "receive",
                        "ok": False, "path": "", "reason": reason})
            return
        path = self._save(f["name"], data)
        self.files[file_id] = path
        self._emit({"type": "file_done", "file_id": file_id, "direction": "receive",
                    "ok": True, "path": path, "reason": ""})

    def _save(self, name, data):
        folder = os.path.join(self.download_dir, self.username or "guest")
        os.makedirs(folder, exist_ok=True)
        base, ext = os.path.splitext(name)
        path = os.path.join(folder, name)
        n = 1
        while os.path.exists(path):             
            path = os.path.join(folder, f"{base} ({n}){ext}")
            n += 1
        with open(path, "wb") as out:
            out.write(data)
        return path

    def _heartbeat(self):
        while self.connected:
            time.sleep(config.HEARTBEAT_INTERVAL)
            if not self.connected:
                return
            try:
                self._send({"type": "HEARTBEAT"})
            except OSError:
                return

    def _emit(self, event):
        try:
            self.on_event(event)
        except Exception:
            pass
