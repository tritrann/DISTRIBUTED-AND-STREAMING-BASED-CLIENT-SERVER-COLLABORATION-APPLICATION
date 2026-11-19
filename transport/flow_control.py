import threading

BUFFER_SIZE = 65535        


class ReceiveBuffer:
    def __init__(self, size=BUFFER_SIZE):
        self.size = size
        self.data = bytearray(size)
        self.read_pos = 0          
        self.write_pos = 0        
        self.used = 0
        self.lock = threading.Lock()

    def free(self):
        with self.lock:
            return self.size - self.used

    def __len__(self):
        with self.lock:
            return self.used

    def write(self, chunk):
        with self.lock:
            n = min(len(chunk), self.size - self.used)
            first = min(n, self.size - self.write_pos)         
            self.data[self.write_pos:self.write_pos + first] = chunk[:first]
            self.data[0:n - first] = chunk[first:n]             
            self.write_pos = (self.write_pos + n) % self.size
            self.used += n
            return n

    def read(self, max_bytes):
        with self.lock:
            n = min(max_bytes, self.used)
            first = min(n, self.size - self.read_pos)
            out = bytes(self.data[self.read_pos:self.read_pos + first]) + bytes(self.data[0:n - first])
            self.read_pos = (self.read_pos + n) % self.size
            self.used -= n
            return out
