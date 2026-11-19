"""Congestion control (design draft, part 3): Custom Multi-Tier AIMD with
real-time in-flight tracking.

Sender state: cwnd and ssthresh (in MSS), dupACKcount, one retransmission
timer for the oldest unACKed byte (kept in reliability.py), MSS.

Sending rule:
    In-Flight = (LastByteSent - LastByteAcked) - dupACKcount * MSS
    send more only while In-Flight < cwnd * MSS

Growth on a NEW ACK:
    slow start            (cwnd < ssthresh):  cwnd += 1        (doubles every RTT)
    congestion avoidance  (cwnd >= ssthresh): cwnd += 1 / cwnd (+1 MSS every RTT)

Three tiers of congestion:
    Tier 1  mild:     3 duplicate ACKs before the timer expires
            ssthresh = max(cwnd/2, 2); cwnd = ssthresh + 3; fast retransmit;
            each further dup ACK: cwnd += 1; NEW ACK: cwnd = ssthresh
            timeout during this recovery (double loss): go to tier 3
    Tier 2  moderate: timeout and dupACKcount is 1 or 2
            ssthresh = max(cwnd/2, 2); cwnd = ssthresh + dupACKcount; retransmit;
            NEW ACK: cwnd = ssthresh (back to congestion avoidance)
    Tier 3  severe:   timeout and dupACKcount == 0
            ssthresh = max(cwnd/2, 2); cwnd = 1; dupACKcount = 0; slow start again
"""

INIT_CWND = 1.0
INIT_SSTHRESH = 16.0
MIN_SSTHRESH = 2.0

NORMAL = "normal"
TIER1 = "tier 1 (mild)"
TIER2 = "tier 2 (moderate)"
TIER3 = "tier 3 (severe)"


class MultiTierAIMD:
    def __init__(self, mss):
        self.mss = mss
        self.cwnd = INIT_CWND            # in MSS
        self.ssthresh = INIT_SSTHRESH    # in MSS
        self.dup_acks = 0                # dupACKcount
        self.state = NORMAL              # NORMAL, or the tier we are recovering from
        self.events = {TIER1: 0, TIER2: 0, TIER3: 0}

    # ---------- sending rule ----------

    def in_flight(self, unacked_bytes):
        return max(0, unacked_bytes - self.dup_acks * self.mss)

    def room(self, unacked_bytes):
        """How many more bytes congestion control allows right now."""
        return int(self.cwnd * self.mss) - self.in_flight(unacked_bytes)

    def phase(self):
        if self.state != NORMAL:
            return "recovery after " + self.state
        return "slow start" if self.cwnd < self.ssthresh else "congestion avoidance"

    # ---------- events ----------

    def on_new_ack(self, acked_bytes):
        """An ACK that moves SendBase forward."""
        self.dup_acks = 0
        if self.state in (TIER1, TIER2):
            self.cwnd = self.ssthresh            # deflate after fast recovery
            self.state = NORMAL
            return
        self.state = NORMAL
        for _ in range(max(1, acked_bytes // self.mss)):
            if self.cwnd < self.ssthresh:
                self.cwnd += 1                   # slow start
            else:
                self.cwnd += 1 / self.cwnd       # congestion avoidance

    def on_dup_ack(self):
        """A duplicate ACK. Returns True when the oldest segment must be resent now."""
        self.dup_acks += 1
        if self.dup_acks == 3 and self.state != TIER1:
            self._cut()
            self.cwnd = self.ssthresh + 3        # 3 segments already left the network
            self.state = TIER1
            self.events[TIER1] += 1
            return True                          # fast retransmit at SendBase
        if self.dup_acks > 3 and self.state == TIER1:
            self.cwnd += 1                       # one more segment has left the network
        return False

    def on_timeout(self):
        """The retransmission timer expired. Returns the tier that was applied."""
        if self.state == TIER1 or self.dup_acks == 0:
            tier = TIER3                         # silent network, or double loss in recovery
            self._cut()
            self.cwnd = INIT_CWND
            self.state = NORMAL
        else:
            tier = TIER2                         # 1 or 2 dup ACKs came back
            self._cut()
            self.cwnd = self.ssthresh + self.dup_acks
            self.state = TIER2
        self.dup_acks = 0
        self.events[tier] += 1
        return tier

    def _cut(self):
        self.ssthresh = max(self.cwnd / 2, MIN_SSTHRESH)
