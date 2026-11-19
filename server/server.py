import errno
import time
import selectors
import sys
import json
import secrets
import argparse
from pathlib import Path

import config
from common.framing import MAX_MESSAGE_SIZE, pack, split
from common.crypto import decrypt_bytes, encode_message
from server.auth import load_users, verify_user
from transport.raw_socket import RawListener

WSAEADDRINUSE = getattr(errno, "WSAEADDRINUSE", None)
WSAEADDRNOTAVAIL = getattr(errno, "WSAEADDRNOTAVAIL", None)
WSAEACCES = getattr(errno, "WSAEACCES", None)

USERS_FILE = Path(__file__).parent / "data" / "users.json"

GUEST_TYPES = {"HELLO", "LOGIN", "BYE", "HEARTBEAT"}

class Server:
    def __init__(self, server_bind_host, server_port):
        self.server_bind_host = server_bind_host
        self.server_port = server_port
        self.listener = None
        self.client_dict = {}
        self.connection_id = 0
        self.running = False
        self.message_handler = {
            "HELLO"      : self._on_hello,
            "LOGIN"      : self._on_login,
            "MSG"        : self._on_msg,
            "USER_LIST"  : self._on_user_list,
            "BYE"        : self._on_bye,
            "HEARTBEAT"  : self._on_heartbeat,
            "FILE_META"  : self._on_file_relay,
            "FILE_CHUNK" : self._on_file_relay,
            "FILE_END"   : self._on_file_relay,
        }
        self.sel = selectors.DefaultSelector()
        self.user_dict = load_users(str(USERS_FILE))
        self.client_by_name = {}

    def start(self):
        try:
            self.listener = RawListener(self.server_bind_host, self.server_port)
        except OSError as err:
            if err.errno in (errno.EADDRINUSE, WSAEADDRINUSE):
                print(f"[ERROR] Port {self.server_port} is already in use by another process!")
            elif err.errno in (errno.EADDRNOTAVAIL, WSAEADDRNOTAVAIL):
                print(f"[ERROR] IP address {self.server_bind_host} does not exist on this machine!")
            elif err.errno in (errno.EACCES, WSAEACCES):
                print(f"[ERROR] Permission denied (Admin/Root required) to bind port {self.server_port}!")
            else:
                print(f"[SYSTEM ERROR] Failed to bind: {err}")
            raise
        self.listener.setblocking(False)
        print(f"[OK] Server is running at {self.server_bind_host}:{self.server_port} (raw TCP) ... ")

        self.sel.register(self.listener, selectors.EVENT_READ, data= "LISTENER")


    def add_client_to_list(self, client_socket, client_address):
        self.connection_id += 1
        client = {
            "socket"       : client_socket,
            "address"      : client_address,
            "conn_id"      : self.connection_id,
            "state"        : "CONNECTED",
            "recv_buffer"  : b"",
            "connected_at" : time.time(),
            "last_seen"    : time.monotonic(),
            "username"     : None,
            "session_id"   : None,
        }
        client_socket.setblocking(False)
        self.client_dict[client_socket] = client
        self.sel.register(client_socket, selectors.EVENT_READ, data=client)
        conn_id = client["conn_id"]

        print(f"[JOIN] conn#{conn_id} {client_address} (total: {len(self.client_dict)})")

    def run(self):
        self.running = True
        while self.running:
            event = self.sel.select(1.0)
            for key, mask in event:
                if key.data == "LISTENER":
                    try:
                        client_socket, client_address = self.listener.accept()
                    except BlockingIOError:
                        continue
                    self.add_client_to_list(client_socket, client_address)
                else :
                    self._handle_client_read(key)
            self._check_heartbeat()

    def close_client(self, client_socket):
        client = self.client_dict.get(client_socket)
        if client is None:
            return
        conn_id = client["conn_id"]
        username = client["username"]
        client_address = client["address"]
        try:
            self.sel.unregister(client_socket)
        except KeyError:
            pass

        try:
            client_socket.close()
        except OSError:
            pass
        self.client_dict.pop(client_socket, None)
        if username is None:
            print(f"[LEAVE] conn#{conn_id} guest {client_address} (total: {len(self.client_dict)}) ")
        else:
            if self.client_by_name.get(username) is client:
                self.client_by_name.pop(username)
                if self.running:
                    self._broadcast({"type": "LEAVE", "username": username})
            print(f"[LEAVE] conn#{conn_id} {username} {client_address} (total: {len(self.client_dict)}) ")

    def _check_heartbeat(self):
        timeout = config.HEARTBEAT_TIMEOUT
        if timeout <= 0:
            return
        now = time.monotonic()
        for client in list(self.client_dict.values()):
            if self.client_dict.get(client["socket"]) is not client:
                continue
            if now - client["last_seen"] > timeout:
                conn_id = client["conn_id"]
                print(f"[TIMEOUT] conn#{conn_id} silent for more than {timeout}s")
                self.close_client(client["socket"])

    def _handle_client_read(self, key: selectors.SelectorKey):
        client_socket = key.fileobj
        client = key.data
        try:
            chunk = client_socket.recv(4096)
        except BlockingIOError:
            return
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            self.close_client(client_socket)
            return
        if chunk == b"" :
            self.close_client(client_socket)
            return
        client["last_seen"] = time.monotonic()
        client["recv_buffer"] += chunk
        try:
            message_list, remain = split(client["recv_buffer"])
        except ValueError:
            self.close_client(client_socket)
            return
        client["recv_buffer"] = remain
        for message in message_list:
            self._handle_message(client, message)
            if self.client_dict.get(client_socket) is None:
                return


    def _handle_message(self, client: dict, message:bytes):
        try:
            message = decrypt_bytes(message)
        except ValueError:
            self._send_error(client, "ERROR", "cannot decrypt message")
            return
        try:
            data = message.decode("utf-8")
            data = json.loads(data)
        except ValueError:
            self._send_error(client, "ERROR" ,"invalid JSON")
            return
        if not isinstance(data, dict):
            self._send_error(client,"ERROR","payload must be a JSON object" )
            return

        message_type = data.get("type")
        if not isinstance(message_type, str):
            self._send_error(client, "ERROR" ,"missing or invalid type")
            return

        handler = self.message_handler.get(message_type)
        if handler is None:
            self._send_error(client, "ERROR",f"unknown type: {message_type}")
            return

        state = client["state"]
        if state == "CONNECTED" and message_type not in GUEST_TYPES:
            self._send_error(client, "ERROR", "not logged in")
            return
        handler(client, data)


    def _send(self, client: dict, message_dict: dict):
        if self.client_dict.get(client["socket"]) is None:
            return False
        message = pack(encode_message(message_dict))
        try:
            client["socket"].sendall(message)
            return True
        except OSError:
            self.close_client(client["socket"])
            return False

    def _send_error(self, client: dict, message_type: str ,reason:str):
        conn_id = client["conn_id"]
        print(f"[{message_type}] conn#{conn_id} {reason}")
        self._send(client, {"type": message_type, "reason": reason})

    def _broadcast(self, message_dict: dict, exclude=None):
        for other in list(self.client_by_name.values()):
            if other is exclude:
                continue
            if self.client_dict.get(other["socket"]) is not other:
                continue
            self._send(other, message_dict)

    def _on_hello(self, client : dict, data : dict):
        self._send(client, {"type": "HELLO_ACK", "conn_id": client["conn_id"]})
        conn_id = client["conn_id"]
        print(f"[HELLO] conn#{conn_id}")

    def _on_login(self, client : dict, data : dict):
        conn_id = client["conn_id"]
        client_state = client["state"]
        if client_state != "CONNECTED":
            self._send_error(client, "ERROR" ,"already logged in")
            return

        username = data.get("username")
        password = data.get("password")
        if (not isinstance(username, str) or not isinstance(password,str) or len(username) == 0):
            self._send_error(client, "LOGIN_FAIL", "invalid login request")
            return
        if len(username) > config.MAX_USERNAME_SIZE:
            self._send_error(client, "LOGIN_FAIL", "username is too long")
            return

        if not verify_user(self.user_dict, username, password):
            self._send_error(client, "LOGIN_FAIL", "wrong username or password")
            print(f"[LOGIN_FAIL] conn#{conn_id} username: {username}")
            return

        if self.client_by_name.get(username) is not None:
            self._send_error(client, "LOGIN_FAIL", "user already online")
            return

        client["username"] = username
        client["session_id"] = secrets.token_hex(16)
        session_id = client["session_id"]
        client_address = client["address"]
        client["state"] = "AUTHENTICATED"
        self.client_by_name[username] = client
        if not self._send(client, {"type": "LOGIN_OK", "username": username,"session_id": session_id}):
            return
        print(f"[LOGIN] conn#{conn_id} username= {username} from {client_address}")

        self._send_user_list(client)
        self._broadcast({"type": "JOIN", "username": username}, exclude=client)

    def _send_user_list(self, client : dict):
        peers = []
        for name in sorted(self.client_by_name):
            address = self.client_by_name[name]["address"]
            peers.append({"username": name, "ip": address[0], "port": address[1]})
        self._send(client, {"type": "USER_LIST", "users": sorted(self.client_by_name), "peers": peers})

    def _on_user_list(self, client : dict, data : dict):
        self._send_user_list(client)

    def _on_msg(self, client : dict, data : dict):
        to = data.get("to")
        text = data.get("text")
        if not isinstance(to, str) or not isinstance(text, str) or len(to) == 0:
            self._send_error(client, "ERROR", "invalid MSG request")
            return
        if len(text) == 0:
            self._send_error(client, "ERROR", "empty message")
            return
        if len(text) > config.MAX_TEXT_LENGTH:
            self._send_error(client, "ERROR", "message is too long")
            return

        sender = client["username"]
        ts = time.time()
        message = {"type": "MSG", "from": sender, "to": to, "text": text, "ts": ts}
        if to == "*":
            self._broadcast(message, exclude=client)
        else:
            target = self.client_by_name.get(to)
            if target is None:
                self._send_error(client, "ERROR", "user offline")
                return
            self._send(target, message)
        self._send(client, {"type": "MSG_ACK", "to": to, "ts": ts})
        print(f"[MSG] {sender} -> {to}")

    def _on_bye(self, client : dict, data : dict):
        conn_id = client["conn_id"]
        print(f"[BYE] conn#{conn_id}")
        self.close_client(client["socket"])

    def _on_heartbeat(self, client : dict, data : dict):
        pass

    def _on_file_relay(self, client : dict, data : dict):
        to = data.get("to")
        if not isinstance(to, str) or len(to) == 0 or to == "*":
            self._send_error(client, "ERROR", "invalid file receiver")
            return
        target = self.client_by_name.get(to)
        if target is None:
            self._send_error(client, "ERROR", "user offline")
            return
        message = dict(data)
        message["from"] = client["username"]
        self._send(target, message)
        message_type = data["type"]
        if message_type != "FILE_CHUNK":
            print(f"[{message_type}] {client['username']} -> {to}")

    def shutdown(self):
        self.running = False
        for client_socket in list(self.client_dict):
            self.close_client(client_socket)
        if self.listener is not None:
            try:
                self.sel.unregister(self.listener)
            except (KeyError, ValueError):
                pass
            try:
                self.listener.close()
            except OSError:
                pass
            self.listener = None
        self.sel.close()
        print("Server stopped")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="StreapRous chat server (raw TCP transport, needs root)")
    parser.add_argument("--host", default=config.SERVER_HOST)
    parser.add_argument("--port", type=int, default=config.SERVER_TCP_PORT)
    args = parser.parse_args()

    server = None
    exit_code = 0
    try:
        server = Server(args.host, args.port)
        server.start()
        server.run()
    except KeyboardInterrupt:
        pass
    except OSError:
        exit_code = 1
    except ValueError:
        exit_code = 1
    finally:
        if server is not None:
            server.shutdown()
    sys.exit(exit_code)