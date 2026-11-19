"""Unit tests for the security layer (common/crypto.py, AES-256-GCM)."""

import unittest

from common.crypto import decode_message, decrypt_bytes, encode_message, encrypt_bytes
from security.security import AESGCMCrypto


class TestCrypto(unittest.TestCase):
    def test_round_trip(self):
        msg = {"type": "MSG", "to": "*", "text": "xin chào"}
        self.assertEqual(decode_message(encode_message(msg)), msg)

    def test_ciphertext_hides_the_text(self):
        data = encode_message({"type": "LOGIN", "username": "tri_demo", "password": "123456"})
        self.assertNotIn(b"123456", data)
        self.assertNotIn(b"LOGIN", data)

    def test_same_message_encrypts_differently(self):
        # a new random nonce every time
        self.assertNotEqual(encrypt_bytes(b"hello"), encrypt_bytes(b"hello"))

    def test_changed_packet_is_rejected(self):
        data = bytearray(encrypt_bytes(b"hello"))
        data[15] ^= 1
        with self.assertRaises(ValueError):
            decrypt_bytes(bytes(data))

    def test_wrong_key_is_rejected(self):
        other = AESGCMCrypto()            # random key
        with self.assertRaises(ValueError):
            decrypt_bytes(other.encrypt(b"hello"))

    def test_plain_json_is_rejected(self):
        with self.assertRaises(ValueError):
            decode_message(b'{"type": "HELLO"}')


if __name__ == "__main__":
    unittest.main()
