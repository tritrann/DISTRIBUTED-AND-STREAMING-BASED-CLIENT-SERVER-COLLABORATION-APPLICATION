"""Packet structure (design draft, part 1: Reliability).

One segment = IP header (20 bytes) + our header (20 bytes) + data.
The header uses the fields chosen in the design draft and keeps the TCP
layout, so the client's operating system can talk to it:

    0                   16                  31
    +-------------------+-------------------+
    |   Source Port     |  Destination Port |   16 bit each: which process
    +-------------------+-------------------+
    |            Sequence Number            |   32 bit: number of the first data byte
    +---------------------------------------+
    |               ACK Number              |   32 bit: next byte we expect (cumulative)
    +---------+---------+-------------------+
    | offset  |  flags  |  Window (rwnd)    |   rwnd = free space in our receive buffer
    +---------+---------+-------------------+
    |     Checksum      |  (unused, 0)      |   16 bit: detects bit errors
    +-------------------+-------------------+
    |                 data ...              |

Length: the total length (header + data) is carried in the IP header and is
also part of the checksum (pseudo header), so a cut segment is detected.

The teacher's StreapRous file is only used for checksum() and
build_ip_header(); everything else here is ours.
"""

import socket
import struct
from collections import namedtuple

from transport import streaprous_raw_connection as raw

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
HEADER_FORMAT = "!HHLLBBHHH"
HEADER_SIZE = 20
SEQ_MOD = 2 ** 32
MAX_WINDOW = 65535

Segment = namedtuple("Segment", "src_ip dst_ip src_port dst_port seq ack flags window length payload valid")


def _pseudo_header(src_ip, dst_ip, length):
    return struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                       0, socket.IPPROTO_TCP, length)


def build_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload=b""):
    """Return a full IP packet ready for sendto() on the raw socket."""
    window = max(0, min(MAX_WINDOW, int(window)))
    header = struct.pack(HEADER_FORMAT, src_port, dst_port, seq % SEQ_MOD, ack % SEQ_MOD,
                         5 << 4, flags, window, 0, 0)
    length = HEADER_SIZE + len(payload)
    check = raw.checksum(_pseudo_header(src_ip, dst_ip, length) + header + payload)
    header = struct.pack(HEADER_FORMAT, src_port, dst_port, seq % SEQ_MOD, ack % SEQ_MOD,
                         5 << 4, flags, window, check, 0)
    return raw.build_ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, length) + header + payload


def checksum_ok(src_ip, dst_ip, tcp_bytes):
    """True if the segment has no bit errors.

    A correct segment sums to 0 together with its pseudo header. Packets that
    another program on the SAME machine sends over loopback are an exception:
    Linux leaves the checksum for the network card to finish ("checksum
    offload"), so the field only holds the pseudo-header sum. We accept that
    exact value too; a real bit error almost never produces it.
    """
    pseudo = _pseudo_header(src_ip, dst_ip, len(tcp_bytes))
    if raw.checksum(pseudo + tcp_bytes) == 0:
        return True
    stored = struct.unpack("!H", tcp_bytes[16:18])[0]
    partial = (~raw.checksum(pseudo)) & 0xFFFF
    return stored == partial


def parse_segment(packet):
    """IP packet -> Segment, or None if it is too short to be one of ours."""
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4
    total_len = struct.unpack("!H", packet[2:4])[0]
    tcp = packet[ihl:total_len]               # cut Ethernet padding, if any
    if len(tcp) < HEADER_SIZE:
        return None
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    src_port, dst_port, seq, ack, offset, flags, window, _check, _urg = \
        struct.unpack(HEADER_FORMAT, tcp[:HEADER_SIZE])
    data_start = (offset >> 4) * 4
    if data_start < HEADER_SIZE or data_start > len(tcp):
        return None
    return Segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window,
                   len(tcp), tcp[data_start:], checksum_ok(src_ip, dst_ip, tcp))
