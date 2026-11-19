import json

import config
from security.security import AESGCMCrypto

_crypto = None


def _get_crypto():
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
    if not config.ENCRYPTION:
        return data
    return _get_crypto().decrypt(data)


def encode_message(message: dict) -> bytes:
    return encrypt_bytes(json.dumps(message).encode("utf-8"))


def decode_message(data: bytes) -> dict:
    message = json.loads(decrypt_bytes(data).decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("message must be a JSON object")
    return message
