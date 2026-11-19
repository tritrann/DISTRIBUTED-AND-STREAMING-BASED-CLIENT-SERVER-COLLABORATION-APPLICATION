

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
        self.cwnd = INIT_CWND            
        self.ssthresh = INIT_SSTHRESH  
        self.dup_acks = 0                
        self.state = NORMAL            
        self.events = {TIER1: 0, TIER2: 0, TIER3: 0}


    def in_flight(self, unacked_bytes):
        return max(0, unacked_bytes - self.dup_acks * self.mss)

    def room(self, unacked_bytes):
        return int(self.cwnd * self.mss) - self.in_flight(unacked_bytes)

    def phase(self):
        if self.state != NORMAL:
            return "recovery after " + self.state
        return "slow start" if self.cwnd < self.ssthresh else "congestion avoidance"


    def on_new_ack(self, acked_bytes):
        self.dup_acks = 0
        if self.state in (TIER1, TIER2):
            self.cwnd = self.ssthresh         
            self.state = NORMAL
            return
        self.state = NORMAL
        for _ in range(max(1, acked_bytes // self.mss)):
            if self.cwnd < self.ssthresh:
                self.cwnd += 1                  
            else:
                self.cwnd += 1 / self.cwnd     

    def on_dup_ack(self):
        self.dup_acks += 1
        if self.dup_acks == 3 and self.state != TIER1:
            self._cut()
            self.cwnd = self.ssthresh + 3        
            self.state = TIER1
            self.events[TIER1] += 1
            return True                    
        if self.dup_acks > 3 and self.state == TIER1:
            self.cwnd += 1                       
        return False

    def on_timeout(self):
        if self.state == TIER1 or self.dup_acks == 0:
            tier = TIER3                       
            self._cut()
            self.cwnd = INIT_CWND
            self.state = NORMAL
        else:
            tier = TIER2                      
            self._cut()
            self.cwnd = self.ssthresh + self.dup_acks
            self.state = TIER2
        self.dup_acks = 0
        self.events[tier] += 1
        return tier

    def _cut(self):
        self.ssthresh = max(self.cwnd / 2, MIN_SSTHRESH)
