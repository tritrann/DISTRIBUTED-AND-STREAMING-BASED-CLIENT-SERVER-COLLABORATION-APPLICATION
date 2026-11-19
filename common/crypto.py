"""Security layer (Step 8).

Every framed message between a client and the server is its JSON text
encrypted with AES-256-GCM, using AESGCMCrypto from security/security.py (TV4).
Wire format of one message body:  nonce (12 bytes) | ciphertext | tag (16 bytes)

Client and server build the same key from config.SHARED_SECRET with PBKDF2,
so a packet sniffer sees only random bytes, and a changed packet is rejected
(GCM tag check fails).
"""

import json

import config
from security.security import AESGCMCrypto

_crypto = None


def _get_crypto():
    # The key is derived once (PBKDF2 is slow on purpose)
    global _crypto
    if _crypto is None:
        _crypto = AESGCMCrypto.from_password(
            config.SHARED_SECRET,
            bytes.fromhex(config.KEY_SALT),
            iterations=config.KEY_ITERATIONS,
        )
    return _crypto


def encrypt_bytes(data: bytes) -> bytes:
    if not config.ENCRYPTION:
        return data
    return _get_crypto().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    """Raise ValueError if the data was not encrypted with our key or was changed."""
    if not config.ENCRYPTION:
        return data
    return _get_crypto().decrypt(data)


def encode_message(message: dict) -> bytes:
    """dict -> encrypted bytes (still needs framing.pack before sending)."""
    return encrypt_bytes(json.dumps(message).encode("utf-8"))


def decode_message(data: bytes) -> dict:
    """Encrypted bytes -> dict. Raise ValueError on a bad key, bad tag or bad JSON."""
    message = json.loads(decrypt_bytes(data).decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("message must be a JSON object")
    return message
