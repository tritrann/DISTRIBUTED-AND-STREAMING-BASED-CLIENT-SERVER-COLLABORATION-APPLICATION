"""Integration tests: real server process + clients over the raw TCP transport.

The server uses SOCK_RAW (teacher's StreapRous files + transport/raw_socket.py), so these tests only
run on Linux/WSL as root. Elsewhere they are skipped. Run from the project root:
    sudo python3 -m unittest tests.test_server -v

Clients are ordinary TCP sockets: the raw transport speaks real TCP on the
wire, so the client's OS does the handshake for it.

The server is started once per test class on a free TCP port and stopped
(with Ctrl+C / SIGINT, so it removes its iptables rule) at the end. Each test uses its own demo accounts so tests do not depend on
each other (accounts: tri_demo, nam_demo, an_demo, binh_demo, user01..user20 / 123456).
All messages are AES-GCM encrypted, like the real client (common/crypto.py).
"""

import hashlib
import json
import threading
import os
import signal
import socket
import subprocess
import tempfile
import sys
import time
import unittest

import config
from client.client import ChatClient
from common.crypto import decode_message, encode_message, encrypt_bytes
from common.framing import pack, split

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "123456"


RUN_SERVER_TESTS = sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


def free_tcp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Client:
    """Small test client: send JSON messages, wait for a given type."""

    def __init__(self, port):
        self.conn = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.conn.setblocking(False)
        self.buffer = b""
        self.inbox = []
        self.closed = False

    def send(self, obj):
        self.conn.sendall(pack(encode_message(obj)))

    def send_raw(self, payload):
        """Encrypted, but the plaintext is not a valid message."""
        self.conn.sendall(pack(encrypt_bytes(payload)))

    def send_plain(self, payload):
        """Not encrypted at all (what a client without the key would send)."""
        self.conn.sendall(pack(payload))

    def _poll(self):
        try:
            data = self.conn.recv(65536)
        except BlockingIOError:
            return False
        except ConnectionResetError:
            data = b""
        if data == b"":
            self.closed = True
            return False
        self.buffer += data
        messages, self.buffer = split(self.buffer)
        for m in messages:
            self.inbox.append(decode_message(m))
        return True

    def wait_for(self, msg_type, timeout=3.0):
        """Return the first message of msg_type (removed from the inbox), or None."""
        deadline = time.time() + timeout
        while True:
            for i, m in enumerate(self.inbox):
                if m.get("type") == msg_type:
                    return self.inbox.pop(i)
            if self.closed or time.time() > deadline:
                return None
            if not self._poll():
                time.sleep(0.02)

    def nothing_of(self, msg_type, wait=0.8):
        """True if no message of msg_type arrives within `wait` seconds."""
        return self.wait_for(msg_type, timeout=wait) is None

    def wait_closed(self, timeout=3.0):
        deadline = time.time() + timeout
        while not self.closed and time.time() < deadline:
            if not self._poll():
                time.sleep(0.02)
        return self.closed

    def login(self, username, password=PASSWORD):
        self.send({"type": "LOGIN", "username": username, "password": password})
        return self.wait_for("LOGIN_OK") or self.wait_for("LOGIN_FAIL", timeout=0.5)

    def close(self):
        try:
            self.conn.close()
        except OSError:
            pass


@unittest.skipUnless(RUN_SERVER_TESTS, "raw TCP server needs Linux/WSL and root (sudo)")
class ServerTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_tcp_port()
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
        cls.log = tempfile.TemporaryFile()
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "server.server", "--host", "127.0.0.1", "--port", str(cls.port)],
            cwd=PROJECT_ROOT, env=env,
            stdout=cls.log, stderr=subprocess.STDOUT,
        )
        # Wait until the server answers HELLO
        deadline = time.time() + 10
        while True:
            try:
                c = Client(cls.port)
                c.send({"type": "HELLO"})
                ok = c.wait_for("HELLO_ACK", timeout=1.0)
                c.close()
                if ok:
                    break
            except (ConnectionError, OSError):
                pass
            if time.time() > deadline or cls.proc.poll() is not None:
                cls.proc.kill()
                cls.proc.wait()
                cls.log.seek(0)
                output = cls.log.read().decode("utf-8", "replace")[-3000:]
                raise RuntimeError("server did not start. Server output:\n" + output)
            time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.proc.send_signal(signal.SIGINT)   # clean shutdown, removes iptables rule
        try:
            cls.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.log.close()

    def setUp(self):
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        time.sleep(0.5)   # let the server process the FINs before the next test

    def new_client(self):
        c = Client(self.port)
        self.clients.append(c)
        return c


class TestHandshakeAndErrors(ServerTestBase):
    def test_hello(self):
        c = self.new_client()
        c.send({"type": "HELLO"})
        self.assertIsNotNone(c.wait_for("HELLO_ACK"))

    def test_invalid_json(self):
        c = self.new_client()
        c.send_raw(b"not json")
        err = c.wait_for("ERROR")
        self.assertEqual(err["reason"], "invalid JSON")

    def test_not_an_object(self):
        c = self.new_client()
        c.send_raw(b"[1,2,3]")
        self.assertIsNotNone(c.wait_for("ERROR"))

    def test_missing_type(self):
        c = self.new_client()
        c.send({"text": "hi"})
        self.assertEqual(c.wait_for("ERROR")["reason"], "missing or invalid type")

    def test_unknown_type(self):
        c = self.new_client()
        c.send({"type": "ABC"})
        self.assertIn("unknown type", c.wait_for("ERROR")["reason"])

    def test_connection_alive_after_errors(self):
        c = self.new_client()
        c.send_raw(b"not json")
        c.wait_for("ERROR")
        c.send({"type": "HELLO"})
        self.assertIsNotNone(c.wait_for("HELLO_ACK"))

    def test_unencrypted_message_rejected(self):
        c = self.new_client()
        c.send_plain(json.dumps({"type": "HELLO"}).encode("utf-8"))
        self.assertEqual(c.wait_for("ERROR")["reason"], "cannot decrypt message")
        self.assertIsNone(c.wait_for("HELLO_ACK", timeout=0.5))

    def test_msg_before_login(self):
        c = self.new_client()
        c.send({"type": "MSG", "to": "*", "text": "x"})
        self.assertEqual(c.wait_for("ERROR")["reason"], "not logged in")


class TestLogin(ServerTestBase):
    def test_login_ok(self):
        c = self.new_client()
        reply = c.login("tri_demo")
        self.assertEqual(reply["type"], "LOGIN_OK")
        self.assertEqual(len(reply["session_id"]), 32)
        users = c.wait_for("USER_LIST")
        self.assertIn("tri_demo", users["users"])

    def test_wrong_password_and_unknown_user_same_reason(self):
        c = self.new_client()
        r1 = c.login("nam_demo", "wrong")
        r2 = c.login("nobody", PASSWORD)
        self.assertEqual(r1["type"], "LOGIN_FAIL")
        self.assertEqual(r2["type"], "LOGIN_FAIL")
        self.assertEqual(r1["reason"], r2["reason"])

    def test_invalid_login_request(self):
        c = self.new_client()
        c.send({"type": "LOGIN", "username": "an_demo"})
        self.assertEqual(c.wait_for("LOGIN_FAIL")["reason"], "invalid login request")

    def test_already_logged_in(self):
        c = self.new_client()
        c.login("binh_demo")
        c.send({"type": "LOGIN", "username": "binh_demo", "password": PASSWORD})
        self.assertEqual(c.wait_for("ERROR")["reason"], "already logged in")

    def test_same_user_online_twice(self):
        a = self.new_client()
        b = self.new_client()
        self.assertEqual(a.login("an_demo")["type"], "LOGIN_OK")
        reply = b.login("an_demo")
        self.assertEqual(reply["type"], "LOGIN_FAIL")
        self.assertEqual(reply["reason"], "user already online")

    def test_login_again_after_close(self):
        a = self.new_client()
        a.login("nam_demo")
        a.close()
        time.sleep(0.5)
        b = self.new_client()
        self.assertEqual(b.login("nam_demo")["type"], "LOGIN_OK")


class TestMessaging(ServerTestBase):
    def setUp(self):
        super().setUp()
        self.tri = self.new_client()
        self.nam = self.new_client()
        self.an = self.new_client()
        self.tri.login("tri_demo")
        self.nam.login("nam_demo")
        self.an.login("an_demo")

    def test_join_received(self):
        # tri logged in first, so it sees nam and an join
        joined = {self.tri.wait_for("JOIN")["username"], self.tri.wait_for("JOIN")["username"]}
        self.assertEqual(joined, {"nam_demo", "an_demo"})

    def test_broadcast(self):
        self.tri.send({"type": "MSG", "to": "*", "text": "hello all"})
        for c in (self.nam, self.an):
            msg = c.wait_for("MSG")
            self.assertEqual(msg["from"], "tri_demo")
            self.assertEqual(msg["text"], "hello all")
        self.assertIsNotNone(self.tri.wait_for("MSG_ACK"))
        self.assertTrue(self.tri.nothing_of("MSG"))

    def test_unicast(self):
        self.tri.send({"type": "MSG", "to": "nam_demo", "text": "only nam"})
        msg = self.nam.wait_for("MSG")
        self.assertEqual((msg["from"], msg["text"]), ("tri_demo", "only nam"))
        self.assertTrue(self.an.nothing_of("MSG"))

    def test_from_cannot_be_faked(self):
        self.tri.send({"type": "MSG", "to": "nam_demo", "text": "x", "from": "an_demo"})
        self.assertEqual(self.nam.wait_for("MSG")["from"], "tri_demo")

    def test_unicast_offline(self):
        self.tri.send({"type": "MSG", "to": "binh_demo", "text": "x"})
        self.assertEqual(self.tri.wait_for("ERROR")["reason"], "user offline")

    def test_empty_message(self):
        self.tri.send({"type": "MSG", "to": "*", "text": ""})
        self.assertEqual(self.tri.wait_for("ERROR")["reason"], "empty message")

    def test_bye_sends_leave(self):
        self.an.send({"type": "BYE"})
        self.assertTrue(self.an.wait_closed())
        for c in (self.tri, self.nam):
            self.assertEqual(c.wait_for("LEAVE")["username"], "an_demo")

    def test_user_list(self):
        self.tri.wait_for("USER_LIST")
        self.tri.send({"type": "USER_LIST"})
        users = self.tri.wait_for("USER_LIST")["users"]
        self.assertEqual(set(users), {"tri_demo", "nam_demo", "an_demo"})

    def test_file_relay(self):
        meta = {"type": "FILE_META", "to": "nam_demo", "name": "a.txt", "size": 3}
        chunk = {"type": "FILE_CHUNK", "to": "nam_demo", "seq": 0, "data": "YWJj"}
        self.tri.send(meta)
        self.tri.send(chunk)
        self.tri.send({"type": "FILE_END", "to": "nam_demo"})
        got_meta = self.nam.wait_for("FILE_META")
        got_chunk = self.nam.wait_for("FILE_CHUNK")
        self.assertEqual(got_meta["from"], "tri_demo")
        self.assertEqual(got_chunk["data"], "YWJj")
        self.assertIsNotNone(self.nam.wait_for("FILE_END"))

    def test_large_message(self):
        text = "x" * 2000
        self.tri.send({"type": "MSG", "to": "nam_demo", "text": text})
        self.assertEqual(self.nam.wait_for("MSG")["text"], text)


    def test_user_list_has_ip_and_port(self):
        self.tri.wait_for("USER_LIST")
        self.tri.send({"type": "USER_LIST"})
        peers = self.tri.wait_for("USER_LIST")["peers"]
        self.assertEqual({p["username"] for p in peers}, {"tri_demo", "nam_demo", "an_demo"})
        for p in peers:
            self.assertEqual(p["ip"], "127.0.0.1")
            self.assertGreater(p["port"], 0)


class TestConcurrency(ServerTestBase):
    """Step 4 / scalability: 20 clients log in at the same time and all chat."""

    def test_twenty_clients(self):
        names = [f"user{i:02d}" for i in range(1, 21)]
        clients = [self.new_client() for _ in names]
        results = {}

        def login(c, name):
            results[name] = c.login(name)

        threads = [threading.Thread(target=login, args=(c, n)) for c, n in zip(clients, names)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertTrue(all(r and r["type"] == "LOGIN_OK" for r in results.values()), results)

        for c, name in zip(clients, names):
            c.send({"type": "MSG", "to": "*", "text": f"hi from {name}"})
        for c, name in zip(clients, names):
            got = set()
            while len(got) < 19:
                msg = c.wait_for("MSG", timeout=10)
                self.assertIsNotNone(msg, f"{name} got only {len(got)} of 19 messages")
                got.add(msg["from"])
            self.assertNotIn(name, got)

        # half of them drop at once; the others see every LEAVE and the server keeps going
        for c in clients[:10]:
            c.close()
        left = set()
        while len(left) < 10:
            msg = clients[10].wait_for("LEAVE", timeout=10)
            self.assertIsNotNone(msg)
            left.add(msg["username"])
        self.assertEqual(left, set(names[:10]))
        clients[11].send({"type": "MSG", "to": names[12], "text": "still working"})
        self.assertEqual(clients[12].wait_for("MSG")["text"], "still working")


class TestResilience(ServerTestBase):
    def test_silent_client_is_closed(self):
        if config.HEARTBEAT_TIMEOUT <= 0:
            self.skipTest("heartbeat is off")
        c = self.new_client()
        c.login("binh_demo")
        watcher = self.new_client()
        watcher.login("an_demo")
        # binh sends nothing, not even HEARTBEAT, so the server must drop it
        self.assertTrue(c.wait_closed(timeout=config.HEARTBEAT_TIMEOUT + 5))
        self.assertEqual(watcher.wait_for("LEAVE", timeout=3)["username"], "binh_demo")

    def test_garbage_frame_closes_only_that_client(self):
        bad = self.new_client()
        good = self.new_client()
        good.login("tri_demo")
        bad.conn.sendall(b"\xff\xff\xff\xff")       # length far above the limit
        self.assertTrue(bad.wait_closed())
        good.send({"type": "USER_LIST"})
        self.assertIsNotNone(good.wait_for("USER_LIST"))


class TestClientLibrary(ServerTestBase):
    """The real client core (client/client.py), as used by the CLI and the web UI."""

    def test_file_transfer_with_hash_check(self):
        folder = tempfile.mkdtemp()
        events = []
        sender = ChatClient(download_dir=folder)
        receiver = ChatClient(on_event=events.append, download_dir=folder)
        try:
            for c, name in ((sender, "tri_demo"), (receiver, "nam_demo")):
                c.connect("127.0.0.1", self.port)
                self.assertEqual(c.login(name, PASSWORD), (True, ""))
            data = os.urandom(1_000_000)
            sender.send_file("nam_demo", "big.bin", data, wait=True)
            deadline = time.time() + 30
            done = []
            while not done and time.time() < deadline:
                done = [e for e in events if e["type"] == "file_done"]
                time.sleep(0.1)
            self.assertTrue(done and done[0]["ok"], done)
            with open(done[0]["path"], "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).digest(), hashlib.sha256(data).digest())
        finally:
            sender.close()
            receiver.close()


if __name__ == "__main__":
    unittest.main()
