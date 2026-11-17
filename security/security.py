from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESGCMCrypto:
    NONCE_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = 32
    DEFAULT_PBKDF2_ITERATIONS = 600_000

    def __init__(self, key: Optional[bytes] = None) -> None:
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"AES-256 key must be {self.KEY_SIZE} bytes")
        self._key = bytes(key)
        self._aesgcm = AESGCM(self._key)

    @classmethod
    def from_password(
        cls,
        password: str,
        salt: bytes,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> "AESGCMCrypto":
        if not password:
            raise ValueError("Password must not be empty")
        if len(salt) < 16:
            raise ValueError("PBKDF2 salt must be at least 16 bytes")
        if iterations < 100_000:
            raise ValueError("PBKDF2 iterations must be at least 100,000")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=iterations,
            dklen=cls.KEY_SIZE,
        ) #Make it random
        return cls(key)

    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(16)

    @property
    def key(self) -> bytes:
        return self._key

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be bytes")
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext_and_tag = self._aesgcm.encrypt(
            nonce,
            plaintext,
            associated_data,
        )
        return nonce + ciphertext_and_tag

    def decrypt(
        self,
        data: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError("Ciphertext is too short")
        nonce = data[: self.NONCE_SIZE]
        ciphertext_and_tag = data[self.NONCE_SIZE :]
        try:
            return self._aesgcm.decrypt(
                nonce,
                ciphertext_and_tag,
                associated_data,
            )
        except InvalidTag as exc:
            raise ValueError(
                "Authentication failed: wrong key or packet was modified"
            ) from exc


@dataclass
class ClientSecurityState:
    last_seen: float = field(default_factory=time.monotonic)
    last_heartbeat_sent: float = 0.0
    missed_heartbeats: int = 0
    is_alive: bool = True
    pending_pings: Dict[int, float] = field(default_factory=dict)

    cubic: "CubicCongestionControl" = field(
        default_factory=lambda: CubicCongestionControl()
    )


class HeartbeatManager:
    def __init__(
        self,
        heartbeat_interval: float = 15.0,
        ack_timeout: float = 10.0,
        max_missed: int = 3,
    ) -> None:
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")
        if ack_timeout <= 0:
            raise ValueError("ack_timeout must be positive")
        if max_missed < 1:
            raise ValueError("max_missed must be at least 1")

        self.heartbeat_interval = heartbeat_interval
        self.ack_timeout = ack_timeout
        self.max_missed = max_missed

    def on_packet_received(self, state: ClientSecurityState) -> None:
        state.last_seen = time.monotonic()

    def should_send_ping(self, state: ClientSecurityState) -> bool:
        now = time.monotonic()
        return state.is_alive and (
            now - state.last_heartbeat_sent >= self.heartbeat_interval
        )

    def mark_ping_sent(
        self,
        state: ClientSecurityState,
        ping_id: int,
    ) -> None:
        if not 0 <= ping_id <= 0xFFFFFFFF:
            raise ValueError("ping_id must be an unsigned 32-bit integer")

        now = time.monotonic()
        state.last_heartbeat_sent = now
        state.pending_pings[ping_id] = now

    def on_heartbeat_ack(
        self,
        state: ClientSecurityState,
        ping_id: int,
    ) -> bool:
        sent_at = state.pending_pings.pop(ping_id, None)
        if sent_at is None:
            return False

        state.last_seen = time.monotonic()
        state.missed_heartbeats = 0
        state.is_alive = True

        for old_ping_id, old_sent_at in list(state.pending_pings.items()):
            if old_sent_at <= sent_at:
                del state.pending_pings[old_ping_id]

        return True

    def check_timeout(self, state: ClientSecurityState) -> bool:
        now = time.monotonic()
        expired_ids = [
            ping_id
            for ping_id, sent_at in state.pending_pings.items()
            if now - sent_at >= self.ack_timeout
        ]

        for ping_id in expired_ids:
            del state.pending_pings[ping_id]
            state.missed_heartbeats += 1

        if state.missed_heartbeats >= self.max_missed:
            state.is_alive = False

        return not state.is_alive

    def safe_close(self, server: object, client_socket: object) -> None:
        try:
            close_client = getattr(server, "close_client")
            close_client(client_socket)
        except Exception as exc:
            print(f"[HEARTBEAT] Could not close client safely: {exc}")


class CubicCongestionControl:
    def __init__(
        self,
        initial_cwnd: float = 2.0,
        min_cwnd: float = 1.0,
        initial_ssthresh: float = 16.0,
        mss: int = 1200,
        beta: float = 0.7,
        C: float = 0.4,
    ) -> None:
        if initial_cwnd <= 0 or min_cwnd <= 0:
            raise ValueError("cwnd values must be positive")
        if initial_ssthresh <= min_cwnd:
            raise ValueError("initial_ssthresh must be greater than min_cwnd")
        if mss <= 0:
            raise ValueError("mss must be positive")
        if not 0 < beta < 1:
            raise ValueError("beta must be between 0 and 1")
        if C <= 0:
            raise ValueError("C must be positive")

        self.cwnd = max(initial_cwnd, min_cwnd)
        self.ssthresh = initial_ssthresh
        self.min_cwnd = min_cwnd
        self.mss = mss
        self.beta = beta
        self.C = C

        self.w_max = self.cwnd
        self.epoch_start: Optional[float] = None
        self.origin_point = self.cwnd
        self.K = 0.0

        self.in_slow_start = self.cwnd < self.ssthresh
        self.packet_count = 0
        self.last_loss_time = 0.0

    def on_ack(self, acked_packets: int = 1) -> None:
        if acked_packets <= 0:
            return

        if self.in_slow_start:
            self.cwnd += acked_packets

            if self.cwnd >= self.ssthresh:
                self.cwnd = max(self.cwnd, self.ssthresh)
                self.in_slow_start = False
                self._start_cubic_epoch()
        else:
            self._cubic_update(acked_packets)

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
        self.packet_count = 0
        self._start_cubic_epoch()

    def can_send(self) -> bool:
        return self.packet_count < max(1, int(self.cwnd))

    def on_packet_sent(self) -> None:
        if not self.can_send():
            raise RuntimeError("Congestion window is full")
        self.packet_count += 1

    def on_packet_acked(self, acked_packets: int = 1) -> None:
        self.on_ack(acked_packets)

    def get_send_rate_bytes_per_sec(self, rtt: float = 0.05) -> float:
        if rtt <= 0:
            raise ValueError("RTT must be positive")
        return (self.cwnd * self.mss) / rtt

    def _start_cubic_epoch(self) -> None:
        self.epoch_start = time.monotonic()
        self.origin_point = self.w_max
        self.K = (
            (self.w_max * (1.0 - self.beta) / self.C) ** (1.0 / 3.0)
        )

    def _cubic_update(self, acked_packets: int) -> None:
        if self.epoch_start is None:
            self._start_cubic_epoch()

        assert self.epoch_start is not None
        elapsed = time.monotonic() - self.epoch_start

        target = (
            self.C * ((elapsed - self.K) ** 3)
            + self.origin_point
        )

        if target > self.cwnd:
            increase = (target - self.cwnd) / max(self.cwnd, 1.0)
            self.cwnd += min(increase, float(acked_packets))
        else:
            self.cwnd += acked_packets / max(self.cwnd, 1.0)

        self.cwnd = max(self.cwnd, self.min_cwnd)


class SecurePacket:
    TYPE_DATA = 0x01
    TYPE_HEARTBEAT = 0x02
    TYPE_ACK = 0x03
    TYPE_CONTROL = 0x04

    LENGTH_SIZE = 4
    HEADER_SIZE = 9
    SEQUENCE_SIZE = 4
    MIN_PACKET_SIZE = HEADER_SIZE + AESGCMCrypto.NONCE_SIZE + AESGCMCrypto.TAG_SIZE
    MAX_PACKET_SIZE = 1200

    VALID_TYPES = {
        TYPE_DATA,
        TYPE_HEARTBEAT,
        TYPE_ACK,
        TYPE_CONTROL,
    }

    @staticmethod
    def pack(
        msg_type: int,
        plaintext: bytes,
        crypto: AESGCMCrypto,
        sequence_number: int = 0,
    ) -> bytes:
        if msg_type not in SecurePacket.VALID_TYPES:
            raise ValueError("Invalid message type")
        if not 0 <= sequence_number <= 0xFFFFFFFF:
            raise ValueError("sequence_number must be an unsigned 32-bit integer")
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        encrypted_size = (
            AESGCMCrypto.NONCE_SIZE
            + len(plaintext)
            + AESGCMCrypto.TAG_SIZE
        )
        length = 1 + SecurePacket.SEQUENCE_SIZE + encrypted_size
        total_size = SecurePacket.LENGTH_SIZE + length

        if total_size > SecurePacket.MAX_PACKET_SIZE:
            raise ValueError(
                f"Packet is {total_size} bytes; maximum is "
                f"{SecurePacket.MAX_PACKET_SIZE} bytes"
            )

        header = struct.pack("!IBI", length, msg_type, sequence_number)

        encrypted = crypto.encrypt(
            plaintext,
            associated_data=header,
        )
        return header + encrypted

    @staticmethod
    def unpack(
        data: bytes,
        crypto: AESGCMCrypto,
    ) -> Tuple[int, int, bytes]:
        if len(data) < SecurePacket.MIN_PACKET_SIZE:
            raise ValueError("Packet is too short")
        if len(data) > SecurePacket.MAX_PACKET_SIZE:
            raise ValueError("Packet exceeds maximum size")

        length, msg_type, sequence_number = struct.unpack(
            "!IBI",
            data[: SecurePacket.HEADER_SIZE],
        )

        if length != len(data) - SecurePacket.LENGTH_SIZE:
            raise ValueError("Invalid packet length")

        if msg_type not in SecurePacket.VALID_TYPES:
            raise ValueError("Invalid message type")

        header = data[: SecurePacket.HEADER_SIZE]
        encrypted = data[SecurePacket.HEADER_SIZE :]

        plaintext = crypto.decrypt(
            encrypted,
            associated_data=header,
        )

        return msg_type, sequence_number, plaintext
