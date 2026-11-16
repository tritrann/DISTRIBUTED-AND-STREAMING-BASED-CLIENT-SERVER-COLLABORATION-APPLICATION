from __future__ import annotations

import os
import time
import struct
import hashlib
from typing import Optional, Tuple
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class AESGCMCrypto:
    NONCE_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = 32

    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-256 key must be {self.KEY_SIZE} bytes")
        self._key = key
        self._aesgcm = AESGCM(key)

    @classmethod
    def from_password(cls, password: str, salt: Optional[bytes] = None) -> "AESGCMCrypto":
        if salt is None:
            salt = b"messaging_app_salt_v1"
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=200_000,
            dklen=cls.KEY_SIZE,
        )
        return cls(key)

    @property
    def key(self) -> bytes:
        return self._key

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        ct = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ct

    def decrypt(self, data: bytes, associated_data: bytes = b"") -> bytes:
        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError("Ciphertext too short")
        nonce = data[: self.NONCE_SIZE]
        ct = data[self.NONCE_SIZE :]
        try:
            return self._aesgcm.decrypt(nonce, ct, associated_data)
        except InvalidTag as e:
            raise ValueError("Authentication failed – packet tampered or wrong key") from e


@dataclass
class ClientSecurityState:
    last_seen: float = field(default_factory=time.monotonic)
    last_heartbeat_sent: float = 0.0
    missed_heartbeats: int = 0
    is_alive: bool = True
    cubic: "CubicCongestionControl" = field(default_factory=lambda: CubicCongestionControl())


class HeartbeatManager:
    def __init__(
        self,
        heartbeat_interval: float = 15.0,
        timeout: float = 45.0,
        max_missed: int = 3,
    ):
        self.heartbeat_interval = heartbeat_interval
        self.timeout = timeout
        self.max_missed = max_missed

    def on_packet_received(self, client_state: ClientSecurityState) -> None:
        client_state.last_seen = time.monotonic()
        client_state.missed_heartbeats = 0
        client_state.is_alive = True

    def should_send_ping(self, client_state: ClientSecurityState) -> bool:
        now = time.monotonic()
        return (now - client_state.last_heartbeat_sent) >= self.heartbeat_interval

    def mark_ping_sent(self, client_state: ClientSecurityState) -> None:
        client_state.last_heartbeat_sent = time.monotonic()

    def check_timeout(self, client_state: ClientSecurityState) -> bool:
        now = time.monotonic()
        silent_time = now - client_state.last_seen
        if silent_time > self.timeout:
            client_state.is_alive = False
            return True
        return False

    def safe_close(self, server, client_socket) -> None:
        try:
            server.close_client(client_socket)
        except Exception as e:
            print(f"[SECURITY] Error while closing client safely: {e}")


class CubicCongestionControl:
    def __init__(
        self,
        initial_cwnd: float = 2.0,
        min_cwnd: float = 1.0,
        mss: int = 1400,
        beta: float = 0.7,
        C: float = 0.4,
    ):
        self.cwnd = initial_cwnd
        self.ssthresh = float("inf")
        self.min_cwnd = min_cwnd
        self.mss = mss
        self.beta = beta
        self.C = C

        self.w_max = initial_cwnd
        self.epoch_start: float = 0.0
        self.origin_point = 0.0
        self.K = 0.0

        self.in_slow_start = True
        self.packet_count = 0
        self.last_loss_time = 0.0

    def on_ack(self, acked_packets: int = 1) -> None:
        if self.in_slow_start:
            self.cwnd += acked_packets
            if self.cwnd >= self.ssthresh:
                self.in_slow_start = False
                self._cubic_reset()
        else:
            self._cubic_update()
            self.cwnd = max(self.cwnd, self.min_cwnd)

        self.packet_count = max(0, self.packet_count - acked_packets)

    def on_loss(self) -> None:
        now = time.monotonic()
        if now - self.last_loss_time < 0.1:
            return
        self.last_loss_time = now

        self.w_max = self.cwnd
        self.ssthresh = max(self.cwnd * self.beta, self.min_cwnd)
        self.cwnd = self.ssthresh
        self.in_slow_start = False
        self._cubic_reset()
        self.packet_count = 0

    def can_send(self) -> bool:
        return self.packet_count < self.cwnd

    def on_packet_sent(self) -> None:
        self.packet_count += 1

    def get_send_rate_bytes_per_sec(self, rtt: float = 0.05) -> float:
        if rtt <= 0:
            rtt = 0.05
        return (self.cwnd * self.mss) / rtt

    def _cubic_reset(self) -> None:
        self.epoch_start = time.monotonic()
        self.origin_point = self.w_max
        self.K = ((self.w_max * (1.0 - self.beta)) / self.C) ** (1.0 / 3.0)

    def _cubic_update(self) -> None:
        t = time.monotonic() - self.epoch_start
        target = self.C * ((t - self.K) ** 3) + self.origin_point
        if target > self.cwnd:
            self.cwnd += (target - self.cwnd) / self.cwnd
        else:
            self.cwnd += 1.0 / self.cwnd


class SecurePacket:
    TYPE_DATA = 0x01
    TYPE_HEARTBEAT = 0x02
    TYPE_ACK = 0x03
    TYPE_CONTROL = 0x04

    @staticmethod
    def pack(msg_type: int, plaintext: bytes, crypto: AESGCMCrypto,
             associated_data: bytes = b"") -> bytes:
        encrypted = crypto.encrypt(plaintext, associated_data)
        length = 1 + len(encrypted)
        header = struct.pack("!IB", length, msg_type)
        return header + encrypted

    @staticmethod
    def unpack(data: bytes, crypto: AESGCMCrypto,
               associated_data: bytes = b"") -> Tuple[int, bytes]:
        if len(data) < 5:
            raise ValueError("Packet too short")
        length, msg_type = struct.unpack("!IB", data[:5])
        encrypted = data[5:]
        plaintext = crypto.decrypt(encrypted, associated_data)
        return msg_type, plaintext
