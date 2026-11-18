import socket
import threading
import time

from transport import streaprous_raw_connection as raw
from transport.streaprous_packet_dispatcher import stop_packet_dispatcher


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
            if not readable and self.has_signal:
                self.reader.recv(16)
                self.has_signal = False
        except OSError:
            pass

    def close(self):
        self.reader.close()
        self.writer.close()


class RawListener:
    def __init__(self, ip, port, make_cc=None):
        self.ip = ip
        self.port = port
        if make_cc is not None:
            raw.set_congestion_control(make_cc)
        raw.setup_rst_block(port, True)
        self.sock = raw.create_raw_socket()
        self.ready = []
        self.lock = threading.Lock()
        self.blocking = True
        self.notifier = Notifier()
        raw.stop_accept = False
        self.running = True
        self.accept_thread = threading.Thread(target=self.accept_loop)
        self.accept_thread.daemon = True
        self.accept_thread.start()

    def accept_loop(self):
        while self.running:
            conn_info = raw.accept(self.sock, self.ip, self.port)
            if conn_info is None:
                break
            tcb = raw.get_tcb(self.sock, conn_info)
            conn = RawConn(self.sock, tcb)
            with self.lock:
                self.ready.append(conn)
                self.notifier.set(True)

    def fileno(self):
        return self.notifier.reader.fileno()

    def setblocking(self, flag):
        self.blocking = flag

    def accept(self):
        while True:
            with self.lock:
                if len(self.ready) > 0:
                    conn = self.ready.pop(0)
                    if len(self.ready) == 0:
                        self.notifier.set(False)
                    return conn, conn.getpeername()
            if not self.blocking:
                raise BlockingIOError("no new connection")
            time.sleep(0.01)

    def close(self):
        self.running = False
        raw.stop_accept = True
        self.accept_thread.join(12)

        all_tcb = []
        with raw.tcb_lock:
            for tcb in raw.tcb_table.values():
                all_tcb.append(tcb)
        for tcb in all_tcb:
            raw.close_connection(self.sock, tcb)

        start = time.time()
        while time.time() - start < 2:
            still_open = 0
            for tcb in all_tcb:
                if tcb.state != "CLOSED":
                    still_open = still_open + 1
            if still_open == 0:
                break
            time.sleep(0.05)
        for tcb in all_tcb:
            with tcb.lock:
                raw.close_tcb(tcb, "server shutdown")

        time.sleep(0.1)
        stop_packet_dispatcher()
        self.sock.close()
        self.notifier.close()
        raw.setup_rst_block(self.port, False)


class RawConn:
    def __init__(self, sock, tcb):
        self.sock = sock
        self.tcb = tcb
        self.blocking = True
        self.notifier = Notifier()
        with tcb.lock:
            tcb.on_event = self.on_event
            self.on_event()

    def on_event(self):
        self.notifier.set(raw.is_readable(self.tcb))

    def fileno(self):
        return self.notifier.reader.fileno()

    def setblocking(self, flag):
        self.blocking = flag

    def getpeername(self):
        return (self.tcb.client_ip, self.tcb.client_port)

    def recv(self, size):
        if not self.blocking and not raw.is_readable(self.tcb):
            raise BlockingIOError("no data yet")
        data = raw.run_conn_recv(self.sock, self.tcb, size)
        if len(data) == 0:
            if self.tcb.close_reason == "reset by peer" or self.tcb.close_reason == "peer not responding":
                raise ConnectionResetError(self.tcb.close_reason)
        return data

    def sendall(self, data):
        result = raw.run_conn_send(self.sock, self.tcb, data)
        if result < 0:
            raise BrokenPipeError("connection is closed")

    def send(self, data):
        self.sendall(data)
        return len(data)

    def close(self):
        with self.tcb.lock:
            self.tcb.on_event = None
        raw.close_connection(self.sock, self.tcb)
        self.notifier.close()

    def get_status(self):
        return raw.get_status(self.tcb)
