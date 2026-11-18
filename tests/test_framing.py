import unittest
import struct
from common.framing import MAX_MESSAGE_SIZE, pack, split

class TestFraming(unittest.TestCase):
    def test_single_message(self):
        data = pack(b"hi")
        message, remainder = split(data)
        self.assertEqual(message, [b"hi"])
        self.assertEqual(remainder,b"")
        
    def test_two_messages_stuck_together(self):
        data = pack(b"hi") + pack(b"abc")
        messages, remainder = split(data)
        self.assertEqual(messages, [b"hi", b"abc"])
        self.assertEqual(remainder, b"")
        
    def test_partial_message(self):
        partial_bytes = pack(b"hello")[:6]
        data = pack(b"hi") + partial_bytes
        messages, remainder = split(data)
        self.assertEqual(messages, [b"hi"])
        self.assertEqual(remainder, partial_bytes)
    
    def test_reassemble_in_two_steps(self):
        full_packet = pack(b"hello")
        first_half = full_packet[:6]
        second_half = full_packet[6:]
        message_1, remainder_1 = split(first_half)
        self.assertEqual(message_1, [])
        message_2, remainder_2 = split(remainder_1 + second_half)
        self.assertEqual(message_2, [b"hello"])
        self.assertEqual(remainder_2, b"")
    
    def test_oversized_length(self):
        oversized_header = struct.pack("!I", MAX_MESSAGE_SIZE + 1)
        with self.assertRaises(ValueError):
            split(oversized_header)
    
    def test_header_not_complete(self):
        data = b"\x00\x00"
        messages, remainder = split(data)
        self.assertEqual(messages, [])
        self.assertEqual(remainder, b"\x00\x00")
        
    def test_http_request_rejected(self):
        http_data = b"GET / HTTP/1.1\r\n"
        with self.assertRaises(ValueError):
            split(http_data)
            
    def test_pack_header(self):
        packed = pack(b"abc")
        self.assertEqual(packed[:4], b"\x00\x00\x00\x03")
        self.assertEqual(packed[4:], b"abc")
        
if __name__ == "__main__":
    unittest.main()