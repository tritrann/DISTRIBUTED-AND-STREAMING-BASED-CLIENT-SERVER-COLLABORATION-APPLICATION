"""Tests for our transport design (design draft: reliability, flow control,
congestion control). No root and no network needed.

A fake raw socket records what the server would put on the wire, and the test
plays the client by putting real (checksummed) segments into the queue.
"""

import contextlib
import io
import random
import struct
import time
import unittest

try:
    from transport import raw_socket as rs
    from transport import streaprous_raw_connection as raw
    from transport.congestion import TIER1, TIER2, TIER3, MultiTierAIMD
    from transport.flow_control import ReceiveBuffer
    from transport.reliability import MSS
    from transport.segment import ACK, FIN, PSH, build_segment, parse_segment
except ImportError:                 # netifaces missing (teacher's file needs it)
    rs = None

C_IP, S_IP, C_PORT, S_PORT = "10.0.0.2", "10.0.0.1", 50000, 9000
ISS, IRS = 2001, 4_000_000_000      # the client's numbers wrap past 2^32
NEEDS = "teacher's transport needs netifaces (sudo apt install python3-netifaces)"


def client_segment(rel_seq, rel_ack, flags, data=b"", window=5840):
    packet = build_segment(C_IP, S_IP, C_PORT, S_PORT, IRS + rel_seq, ISS + rel_ack,
                           flags, window, data)
    return packet + b"\0" * 6       # Ethernet-style padding must be ignored


class FakeSock:
    def __init__(self):
        self.out = []                # parsed segments the server sent

    def sendto(self, packet, addr):
        seg = parse_segment(packet)
        assert seg.valid, "server sent a bad checksum"
        self.out.append(seg._replace(seq=(seg.seq - ISS) % 2 ** 32, ack=(seg.ack - IRS) % 2 ** 32))
        return len(packet)

    def take(self):
        out, self.out = self.out, []
        return out


# ======================= part 1: packet structure =======================

@unittest.skipIf(rs is None, NEEDS)
class TestSegment(unittest.TestCase):
    def test_round_trip(self):
        seg = parse_segment(build_segment(S_IP, C_IP, 9000, 50000, 7, 9, ACK | PSH, 1234, b"hello"))
        self.assertTrue(seg.valid)
        self.assertEqual((seg.src_port, seg.dst_port, seg.seq, seg.ack, seg.window, seg.payload),
                         (9000, 50000, 7, 9, 1234, b"hello"))
        self.assertEqual(seg.length, 20 + 5)

    def test_bit_error_is_detected(self):
        packet = bytearray(build_segment(S_IP, C_IP, 9000, 50000, 7, 9, ACK, 100, b"hello"))
        packet[-1] ^= 0x01
        self.assertFalse(parse_segment(bytes(packet)).valid)

    def test_loopback_checksum_offload_is_accepted(self):
        packet = bytearray(build_segment(C_IP, S_IP, 50000, 9000, 1, 1, ACK, 100, b"abc"))
        tcp_len = len(packet) - 20
        pseudo = struct.pack("!4s4sBBH", bytes(packet[12:16]), bytes(packet[16:20]), 0, 6, tcp_len)
        packet[36:38] = struct.pack("!H", (~raw.checksum(pseudo)) & 0xFFFF)   # what Linux leaves on lo
        self.assertTrue(parse_segment(bytes(packet)).valid)


# ======================= part 2: flow control buffer =======================

@unittest.skipIf(rs is None, NEEDS)
class TestReceiveBuffer(unittest.TestCase):
    def test_wraps_around(self):
        b = ReceiveBuffer(10)
        self.assertEqual(b.write(b"abcdefgh"), 8)
        self.assertEqual(b.read(6), b"abcdef")
        self.assertEqual(b.write(b"123456"), 6)       # wraps past the end of the array
        self.assertEqual(b.read(100), b"gh123456")
        self.assertEqual(b.free(), 10)

    def test_never_overflows(self):
        b = ReceiveBuffer(10)
        self.assertEqual(b.write(b"x" * 25), 10)
        self.assertEqual(b.free(), 0)
        self.assertEqual(b.write(b"more"), 0)


# ======================= part 3: congestion control =======================

@unittest.skipIf(rs is None, NEEDS)
class TestMultiTierAIMD(unittest.TestCase):
    def make(self, cwnd):
        cc = MultiTierAIMD(MSS)
        cc.cwnd = cwnd
        return cc

    def test_slow_start_then_congestion_avoidance(self):
        cc = MultiTierAIMD(MSS)
        cc.ssthresh = 4
        for _ in range(3):
            cc.on_new_ack(MSS)
        self.assertEqual(cc.cwnd, 4)                   # 1 -> 2 -> 3 -> 4
        cc.on_new_ack(MSS)
        self.assertAlmostEqual(cc.cwnd, 4.25)          # + 1/cwnd

    def test_in_flight_formula(self):
        cc = self.make(10)
        cc.dup_acks = 2
        self.assertEqual(cc.in_flight(5000), 3000)     # (sent - acked) - dup * MSS
        self.assertEqual(cc.room(5000), 7000)

    def test_tier1_three_dup_acks(self):
        cc = self.make(10)
        self.assertFalse(cc.on_dup_ack())
        self.assertFalse(cc.on_dup_ack())
        self.assertTrue(cc.on_dup_ack())               # fast retransmit now
        self.assertEqual((cc.ssthresh, cc.cwnd), (5, 8))
        cc.on_dup_ack()
        self.assertEqual(cc.cwnd, 9)                   # 4th dup ACK: +1
        cc.on_new_ack(MSS)
        self.assertEqual(cc.cwnd, 5)                   # deflate to ssthresh
        self.assertEqual(cc.events[TIER1], 1)

    def test_tier2_timeout_after_some_dup_acks(self):
        cc = self.make(10)
        cc.on_dup_ack()
        cc.on_dup_ack()
        self.assertEqual(cc.on_timeout(), TIER2)
        self.assertEqual((cc.ssthresh, cc.cwnd), (5, 7))   # ssthresh + 2
        cc.on_new_ack(MSS)
        self.assertEqual(cc.cwnd, 5)

    def test_tier3_silent_timeout(self):
        cc = self.make(10)
        self.assertEqual(cc.on_timeout(), TIER3)
        self.assertEqual((cc.ssthresh, cc.cwnd, cc.dup_acks), (5, 1, 0))

    def test_double_loss_in_fast_recovery(self):
        cc = self.make(10)
        for _ in range(3):
            cc.on_dup_ack()                            # cwnd = 8
        self.assertEqual(cc.on_timeout(), TIER3)
        self.assertEqual((cc.ssthresh, cc.cwnd), (4, 1))

    def test_ssthresh_floor(self):
        cc = self.make(1)
        cc.on_timeout()
        self.assertEqual(cc.ssthresh, 2)


# ======================= whole connection =======================

@unittest.skipIf(rs is None, NEEDS)
class TestConnection(unittest.TestCase):
    def setUp(self):
        self.quiet = contextlib.redirect_stdout(io.StringIO())   # teacher's code prints a lot
        self.quiet.__enter__()
        self.old_loss = rs.LOSS_RATE
        self.sock = FakeSock()
        info = raw.conn_struct(C_IP, C_PORT, S_IP, S_PORT, "ESTABLISHED", ISS, IRS, 0, time.time())
        self.raw_conn = rs.RawConn(self.sock, info)
        self.raw_conn.setblocking(False)
        self.conn = self.raw_conn.conn

    def tearDown(self):
        rs.LOSS_RATE = self.old_loss
        with self.raw_conn.lock:
            self.conn.closed = True
        self.raw_conn.worker.join(1)
        self.quiet.__exit__(None, None, None)

    def feed(self, *packets, wait=0.1):
        for p in packets:
            self.raw_conn.queue.put((p, None))
        time.sleep(wait)

    # ---- reliability ----

    def test_out_of_order_data_is_delivered_in_order(self):
        self.feed(client_segment(5, 0, ACK | PSH, b"world"))
        with self.assertRaises(BlockingIOError):
            self.raw_conn.recv(100)
        self.assertEqual(self.sock.take()[-1].ack, 0)        # still asks for byte 0
        self.feed(client_segment(0, 0, ACK | PSH, b"hello"))
        self.assertEqual(self.raw_conn.recv(100), b"helloworld")
        self.assertEqual(self.sock.take()[-1].ack, 10)

    def test_duplicate_data_is_not_delivered_twice(self):
        self.feed(client_segment(0, 0, ACK | PSH, b"abc"), client_segment(0, 0, ACK | PSH, b"abc"))
        self.assertEqual(self.raw_conn.recv(100), b"abc")
        with self.assertRaises(BlockingIOError):
            self.raw_conn.recv(100)

    def test_bad_checksum_is_dropped_and_reported(self):
        bad = bytearray(client_segment(0, 0, ACK | PSH, b"hello"))
        bad[44] ^= 0xFF                                      # flip bits in the data
        self.feed(bytes(bad))
        with self.assertRaises(BlockingIOError):
            self.raw_conn.recv(100)
        self.assertEqual(self.conn.checksum_errors, 1)
        self.assertEqual(self.sock.take()[-1].ack, 0)        # duplicate ACK: "send 0 again"

    def run_transfer(self, data, drop_first_copy_of=(), timeout=20, ack_window=5840):
        """Act as a receiver that ACKs what it has; return the bytes it got."""
        self.raw_conn.sendall(data)
        got, dropped, deadline = {}, set(), time.time() + timeout
        next_byte = 0
        while next_byte < len(data) and time.time() < deadline:
            time.sleep(0.03)
            for seg in self.sock.take():
                if not seg.payload:
                    continue
                if seg.seq in drop_first_copy_of and seg.seq not in dropped:
                    dropped.add(seg.seq)
                    continue
                got[seg.seq] = seg.payload
            while next_byte in got:
                next_byte += len(got[next_byte])
            self.feed(client_segment(0, next_byte, ACK, window=ack_window), wait=0)
        # rebuild the stream by following the segments from byte 0 (they may overlap)
        out, pos = bytearray(), 0
        while pos in got and pos < len(data):
            out += got[pos]
            pos += len(got[pos])
        return bytes(out[:len(data)])

    def test_window_grows_in_slow_start(self):
        self.assertEqual(self.conn.cc.cwnd, 1)
        data = bytes(range(256)) * 40                         # 10 KB
        self.assertEqual(self.run_transfer(data), data)
        self.assertGreater(self.conn.cc.cwnd, 4)
        self.assertEqual(self.conn.retransmissions, 0)

    def test_lost_segment_triggers_tier1(self):
        data = bytes(range(256)) * 40
        self.assertEqual(self.run_transfer(data, drop_first_copy_of={3000}), data)
        self.assertGreaterEqual(self.conn.retransmissions, 1)
        self.assertGreaterEqual(self.conn.cc.events[TIER1] + self.conn.cc.events[TIER2], 1)

    def test_silent_receiver_triggers_tier3(self):
        self.raw_conn.sendall(b"x" * 500)
        time.sleep(0.8)                                       # > RTO 0.5 s, nobody ACKs
        self.assertGreaterEqual(self.conn.cc.events[TIER3], 1)
        self.assertEqual(self.conn.cc.cwnd, 1)
        self.assertGreaterEqual(self.conn.retransmissions, 1)

    def test_random_loss_still_delivers_everything(self):
        random.seed(3)                                        # same drop pattern every run
        rs.LOSS_RATE = 0.2
        data = bytes(range(256)) * 80                         # 20 KB, 20 % of packets dropped
        self.assertEqual(self.run_transfer(data, timeout=60), data)
        self.assertGreater(self.conn.retransmissions, 0)

    # ---- flow control ----

    def test_ack_carries_free_buffer_space(self):
        self.feed(client_segment(0, 0, ACK | PSH, b"a" * 3000))
        self.assertEqual(self.sock.take()[-1].window, 65535 - 3000)
        self.raw_conn.recv(3000)
        self.feed(client_segment(3000, 0, ACK | PSH, b"b"))
        self.assertEqual(self.sock.take()[-1].window, 65535 - 1)

    def test_full_buffer_stops_accepting_then_reopens(self):
        segments = [client_segment(i, 0, ACK | PSH, b"z" * 1000) for i in range(0, 70000, 1000)]
        self.feed(*segments, wait=0.5)
        last = self.sock.take()[-1]
        self.assertEqual(last.ack, 65535)                     # only what fits is ACKed
        self.assertEqual(last.window, 0)
        self.assertEqual(len(self.raw_conn.recv(10000)), 10000)
        update = self.sock.take()[-1]                         # window update after reading
        self.assertEqual(update.window, 10000)

    def test_sender_respects_receiver_window(self):
        self.feed(client_segment(0, 0, ACK, window=2000))     # client: only 2000 bytes free
        self.conn.cc.cwnd = 50                                # congestion window is not the limit
        self.raw_conn.sendall(b"d" * 10000)
        time.sleep(0.2)
        sent = sum(len(s.payload) for s in self.sock.take())
        self.assertEqual(sent, 2000)

    def test_close_sends_fin_and_finishes(self):
        self.raw_conn.close()
        time.sleep(0.1)
        self.assertTrue([s for s in self.sock.take() if s.flags & FIN])
        self.feed(client_segment(0, 1, ACK | FIN), wait=0.3)   # client ACKs our FIN and sends its own
        self.assertTrue(self.conn.closed)
        self.assertEqual(self.conn.close_reason, "closed")


if __name__ == "__main__":
    unittest.main()
