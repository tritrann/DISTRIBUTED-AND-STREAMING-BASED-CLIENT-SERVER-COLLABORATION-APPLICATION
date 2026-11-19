"""Flow control (design draft, part 2).

The receiver keeps a fixed 64 KB circular buffer. The network thread writes
at the write pointer, the application reads at the read pointer; both wrap
around the same array, so reading frees space at once without moving data.
A mutex protects the two pointers from the two threads.

rwnd = free space in this buffer. It is sent back in every ACK (Window field),
and the sender never has more unacknowledged bytes in flight than the
receiver's last rwnd. Data that does not fit is not accepted (not ACKed), so
the buffer can never overflow.
"""

import threading

BUFFER_SIZE = 65535        # 64 KB, the largest value the 16-bit Window field can carry


class ReceiveBuffer:
    def __init__(self, size=BUFFER_SIZE):
        self.size = size
        self.data = bytearray(size)
        self.read_pos = 0          # application reads here
        self.write_pos = 0         # network thread writes here
        self.used = 0
        self.lock = threading.Lock()

    def free(self):
        """rwnd: how many more bytes we can accept."""
        with self.lock:
            return self.size - self.used

    def __len__(self):
        with self.lock:
            return self.used

    def write(self, chunk):
        """Store as much of chunk as fits; return how many bytes were stored."""
        with self.lock:
            n = min(len(chunk), self.size - self.used)
            first = min(n, self.size - self.write_pos)          # up to the end of the array
            self.data[self.write_pos:self.write_pos + first] = chunk[:first]
            self.data[0:n - first] = chunk[first:n]             # the rest wraps to the start
            self.write_pos = (self.write_pos + n) % self.size
            self.used += n
            return n

    def read(self, max_bytes):
        """Take up to max_bytes from the buffer (frees that space)."""
        with self.lock:
            n = min(max_bytes, self.used)
            first = min(n, self.size - self.read_pos)
            out = bytes(self.data[self.read_pos:self.read_pos + first]) + bytes(self.data[0:n - first])
            self.read_pos = (self.read_pos + n) % self.size
            self.used -= n
            return out
