"""Reliability (design draft, part 1) for one connection, plus the glue to
flow control (part 2) and congestion control (part 3).

Goal: data is not lost, not corrupted and arrives in order.

    Sender                                   Receiver
    ------                                   --------
    cut data into segments (<= MSS)          check the checksum; a bad segment is
    number them by byte (seq)                dropped and answered with a duplicate ACK
    keep them until ACKed (send buffer)      put early segments aside (out_of_order)
    sliding window: send while               deliver in order into the 64 KB buffer
      In-Flight < cwnd and < peer rwnd       ACK = next byte expected (cumulative),
    ONE timer for the oldest unACKed byte     Window = free space (rwnd)
    timeout / 3 dup ACKs -> resend oldest

The class has no socket and no thread: raw_socket.py feeds it parsed segments
and calls check_timer(); it sends through the output() callback. That keeps
it easy to test.

Sequence numbers are counted from 0 after the handshake (the real 32-bit
numbers are iss/irs + offset), so wrap-around past 2^32 is handled.
"""

import time

from transport.congestion import MultiTierAIMD
from transport.flow_control import ReceiveBuffer
from transport.segment import ACK, FIN, PSH, RST, SEQ_MOD, SYN

MSS = 1000             # bytes of data per segment (IP 20 + header 20 + 1000 < 1500 MTU)
INIT_RTO = 0.5         # retransmission timeout (seconds); the draft does not measure RTT
MAX_RTO = 8.0          # the timeout doubles after each timeout, up to this
DEAD_TIME = 15.0       # give up if the peer says nothing while data waits for an ACK
FIN_WAIT_TIME = 5.0    # after our FIN is ACKed, wait this long for the peer's FIN


class ReliableConnection:
    def __init__(self, iss, irs, output, mss=MSS):
        """iss/irs: first data sequence numbers of us / the peer (from the handshake).
        output(seq, ack, flags, window, payload) puts one segment on the wire."""
        self.iss = iss
        self.irs = irs
        self.output = output
        self.mss = mss
        self.cc = MultiTierAIMD(mss)            # part 3
        self.rbuf = ReceiveBuffer()             # part 2

        # sender
        self.send_buf = b""        # bytes from SendBase on (sent or not yet sent)
        self.snd_una = 0           # SendBase / LastByteAcked
        self.snd_nxt = 0           # LastByteSent + 1
        self.peer_window = 5840    # peer's rwnd (updated by every ACK)
        self.rto = INIT_RTO
        self.timer = None          # when the oldest unACKed segment was (re)sent
        self.retransmissions = 0

        # receiver
        self.rcv_nxt = 0           # next byte expected from the peer
        self.out_of_order = {}     # start seq -> data that arrived early
        self.advertised = self.rbuf.size
        self.checksum_errors = 0

        # closing
        self.want_close = False
        self.fin_seq = None
        self.fin_acked = False
        self.fin_acked_time = 0.0
        self.peer_closed = False
        self.closed = False
        self.close_reason = ""
        self.last_heard = time.time()

    # ================= sending segments =================

    def _emit(self, rel_seq, flags, payload=b""):
        self.advertised = self.rbuf.free()
        self.output((self.iss + rel_seq) % SEQ_MOD, (self.irs + self.rcv_nxt) % SEQ_MOD,
                    flags | ACK, self.advertised, payload)

    def send_ack(self):
        self._emit(self.snd_nxt, 0)

    def send_more(self):
        """Sliding window: send new data while both windows allow it."""
        if self.closed or self.fin_seq is not None:
            return
        unacked = self.snd_nxt - self.snd_una
        unsent = len(self.send_buf) - unacked
        while unsent > 0:
            room = min(self.cc.room(unacked), self.peer_window - unacked)
            if room <= 0:
                if self.peer_window == 0 and unacked == 0:
                    room = 1                 # zero-window probe: ask again with 1 byte
                else:
                    break
            size = min(self.mss, unsent, room)
            self._emit(self.snd_nxt, PSH, self.send_buf[unacked:unacked + size])
            self.snd_nxt += size
            unacked += size
            unsent -= size
            if self.timer is None:
                self.timer = time.time()
        if self.want_close and unsent == 0:
            self.fin_seq = self.snd_nxt
            self._emit(self.fin_seq, FIN)
            self.snd_nxt += 1                # FIN uses one sequence number
            if self.timer is None:
                self.timer = time.time()

    def _resend_oldest(self):
        """Resend only the segment at SendBase (the receiver keeps later ones)."""
        data_unacked = self.snd_nxt - self.snd_una
        if self.fin_seq is not None and not self.fin_acked:
            data_unacked -= 1
        if data_unacked > 0:
            self._emit(self.snd_una, PSH, self.send_buf[:min(self.mss, data_unacked)])
        elif self.fin_seq is not None and not self.fin_acked:
            self._emit(self.fin_seq, FIN)
        else:
            return
        self.retransmissions += 1
        self.timer = time.time()

    # ================= receiving segments =================

    def on_segment(self, seg):
        if not seg.valid:
            # bit error: drop it and tell the sender what we still expect
            self.checksum_errors += 1
            self.send_ack()
            return
        self.last_heard = time.time()
        if seg.flags & RST:
            self.closed = True
            self.close_reason = "reset by peer"
            return
        if seg.flags & SYN:
            return                           # late handshake packet
        if seg.flags & ACK:
            pure = len(seg.payload) == 0 and not seg.flags & FIN
            self._on_ack((seg.ack - self.iss) % SEQ_MOD, seg.window, pure)
        if seg.payload or seg.flags & FIN:
            self._on_data((seg.seq - self.irs) % SEQ_MOD, seg.payload, seg.flags & FIN)

    def _on_ack(self, ack, window, pure):
        old_window = self.peer_window
        self.peer_window = window            # flow control: the peer's rwnd
        if ack > self.snd_nxt:
            return                           # ACKs data we never sent
        if ack > self.snd_una:               # NEW ACK
            acked = ack - self.snd_una
            if self.fin_seq is not None and ack == self.fin_seq + 1:
                self.fin_acked = True
                self.fin_acked_time = time.time()
                acked -= 1
            self.send_buf = self.send_buf[acked:]
            self.snd_una = ack
            self.cc.on_new_ack(acked)
            self.rto = INIT_RTO
            self.timer = time.time() if self.snd_una < self.snd_nxt else None
        elif ack == self.snd_una and pure and window == old_window and self.snd_una < self.snd_nxt:
            if self.cc.on_dup_ack():         # tier 1: 3 duplicate ACKs
                self._resend_oldest()

    def _on_data(self, rel_seq, data, fin):
        diff = (rel_seq - self.rcv_nxt) % SEQ_MOD
        if diff >= SEQ_MOD // 2:
            diff -= SEQ_MOD                  # negative: starts before rcv_nxt (old data)
        start = self.rcv_nxt + diff
        end = start + len(data)
        if diff < 0:
            data = data[-diff:]
            start = self.rcv_nxt

        if data:
            if start == self.rcv_nxt:
                self._deliver(data)
            elif start < self.rcv_nxt + self.rbuf.free():
                self.out_of_order[start] = data          # inside our window: keep it
            # beyond our window: drop it, the sender ignored rwnd

        if fin and end == self.rcv_nxt and not self.peer_closed:
            self.peer_closed = True
            self.rcv_nxt += 1                # FIN uses one sequence number
        self.send_ack()                      # cumulative ACK + current rwnd

    def _deliver(self, data):
        """Write in-order data into the 64 KB buffer, then any early data that now fits."""
        stored = self.rbuf.write(data)
        self.rcv_nxt += stored
        if stored < len(data):
            return                           # buffer full: the rest is not ACKed
        while self.rcv_nxt in self.out_of_order:
            more = self.out_of_order.pop(self.rcv_nxt)
            stored = self.rbuf.write(more)
            self.rcv_nxt += stored
            if stored < len(more):
                self.out_of_order[self.rcv_nxt] = more[stored:]
                break
        for old in [s for s in self.out_of_order if s < self.rcv_nxt]:
            del self.out_of_order[old]

    # ================= timer =================

    def check_timer(self, now=None):
        now = time.time() if now is None else now
        if self.fin_acked and (self.peer_closed or now - self.fin_acked_time > FIN_WAIT_TIME):
            self.closed = True
            self.close_reason = "closed"
            return
        if self.timer is None or now - self.timer < self.rto:
            return
        if now - self.last_heard > DEAD_TIME:
            self.closed = True
            self.close_reason = "peer not responding"
            return
        if self.peer_window > 0:
            self.cc.on_timeout()             # tier 2 or tier 3
        # (a timeout while the peer's window is 0 is flow control, not congestion)
        self.rto = min(self.rto * 2, MAX_RTO)
        self._resend_oldest()

    # ================= application side =================

    def write(self, data):
        self.send_buf += data
        self.send_more()

    def read(self, max_bytes):
        data = self.rbuf.read(max_bytes)
        # window update: tell the sender as soon as space opens after a (nearly) full buffer
        if data and self.advertised < self.mss and self.rbuf.free() >= self.mss:
            self.send_ack()
        return data

    def readable(self):
        return len(self.rbuf) > 0 or self.peer_closed or self.closed

    def close(self):
        self.want_close = True
        self.send_more()

    def status(self):
        unacked = self.snd_nxt - self.snd_una
        return {
            "cwnd": round(self.cc.cwnd, 2),
            "ssthresh": round(self.cc.ssthresh, 2),
            "phase": self.cc.phase(),
            "dup_acks": self.cc.dup_acks,
            "in_flight": self.cc.in_flight(unacked),
            "peer_rwnd": self.peer_window,
            "our_rwnd": self.rbuf.free(),
            "rto": self.rto,
            "retransmissions": self.retransmissions,
            "checksum_errors": self.checksum_errors,
            "congestion_events": dict(self.cc.events),
            "closed": self.closed,
        }
