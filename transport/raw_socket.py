
import platform
import queue
import random
import socket
import subprocess
import threading
import time

from transport import streaprous_raw_connection as raw
from transport.streaprous_packet_dispatcher import (
    get_packet_queue,
    remove_packet_queue,
    stop_packet_dispatcher,
)
from transport.reliability import ReliableConnection
from transport.segment import build_segment, parse_segment

LOSS_RATE = 0.0       
TICK = 0.02           


def set_rst_block(port, enable):
    if platform.system() != "Linux":
        return
    action = "-A" if enable else "-D"
    subprocess.run(["iptables", action, "OUTPUT", "-p", "tcp", "--sport", str(port),
                    "--tcp-flags", "RST", "RST", "-j", "DROP"], capture_output=True)


class Notifier:
    def __init__(self):
        self.reader, self.writer = socket.socketpair()
        self.reader.setblocking(False)
        self.writer.setblocking(False)
        self.has_signal = False

    def set(self, readable):
        try:
            if readable and not self.has_signal:
                self.writer.send(b"x")
                self.has_signal = True
            elif not readable and self.has_signal:
                self.reader.recv(16)
                self.has_signal = False
        except OSError:
            pass   

    def close(self):
        self.reader.close()
        self.writer.close()


class RawConn:
    def __init__(self, sock, info):
        self.sock = sock
        self.client_ip = info.client_ip
        self.client_port = info.client_port
        self.server_ip = info.server_ip
        self.server_port = info.server_port
        self.key = (self.client_ip, self.client_port)
        self.queue = get_packet_queue(self.key)
        self.conn = ReliableConnection(info.server_seq, info.client_seq, self._output)
        self.blocking = True
        self.lock = threading.Lock()
        self.notifier = Notifier()
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    @property
    def closed(self):
        return self.conn.closed

    def _output(self, seq, ack, flags, window, payload):
        if random.random() < LOSS_RATE:
            return
        packet = build_segment(self.server_ip, self.client_ip, self.server_port, self.client_port,
                               seq, ack, flags, window, payload)
        try:
            self.sock.sendto(packet, (self.client_ip, 0))
        except OSError:
            pass

    def _worker(self):
        while True:
            try:
                packet, _ = self.queue.get(timeout=TICK)
            except queue.Empty:
                packet = None
            with self.lock:
                if packet is not None and random.random() >= LOSS_RATE:
                    seg = parse_segment(packet)
                    if seg is not None and seg.src_port == self.client_port and seg.dst_port == self.server_port:
                        self.conn.on_segment(seg)
                if not self.conn.closed:
                    self.conn.check_timer()
                if not self.conn.closed:
                    self.conn.send_more()
                self.notifier.set(self.conn.readable())
                if self.conn.closed:
                    break
        remove_packet_queue(self.key)
        with raw.connections_lock:
            raw.connections.pop(self.key, None)
            
    def fileno(self):
        return self.notifier.reader.fileno()

    def setblocking(self, flag):
        self.blocking = flag

    def getpeername(self):
        return self.key

    def recv(self, size):
        while True:
            with self.lock:
                data = self.conn.read(size)
                if data:
                    self.notifier.set(self.conn.readable())
                    return data
                if self.conn.closed and self.conn.close_reason != "closed":
                    raise ConnectionResetError(self.conn.close_reason)
                if self.conn.peer_closed or self.conn.closed:
                    return b""
            if not self.blocking:
                raise BlockingIOError("no data yet")
            time.sleep(0.01)

    def sendall(self, data):
        with self.lock:
            if self.conn.closed or self.conn.want_close:
                raise BrokenPipeError("connection is closed")
            self.conn.write(data)

    def send(self, data):
        self.sendall(data)
        return len(data)

    def close(self):
        with self.lock:
            self.conn.close()
        self.notifier.close()

    def get_status(self):
        with self.lock:
            status = self.conn.status()
        status["client"] = f"{self.client_ip}:{self.client_port}"
        return status


class RawListener:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = raw.create_raw_socket()   
        set_rst_block(port, True)
        self.ready = []
        self.conns = []
        self.lock = threading.Lock()
        self.blocking = True
        self.notifier = Notifier()
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                info = raw.accept(self.sock, self.ip, self.port)
            except Exception:
                break           
            if info is None or not self.running:
                continue
            conn = RawConn(self.sock, info)
            with self.lock:
                self.ready.append(conn)
                self.conns = [c for c in self.conns if not c.closed] + [conn]
                self.notifier.set(True)

    def fileno(self):
        return self.notifier.reader.fileno()

    def setblocking(self, flag):
        self.blocking = flag

    def accept(self):
        while True:
            with self.lock:
                if self.ready:
                    conn = self.ready.pop(0)
                    if not self.ready:
                        self.notifier.set(False)
                    return conn, conn.getpeername()
            if not self.blocking:
                raise BlockingIOError("no new connection")
            time.sleep(0.01)

    def close(self):
        self.running = False
        deadline = time.time() + 2    
        while time.time() < deadline and any(not c.closed for c in self.conns):
            time.sleep(0.05)
        stop_packet_dispatcher()
        try:
            self.sock.close()
        except OSError:
            pass
        self.notifier.close()
        set_rst_block(self.port, False)
