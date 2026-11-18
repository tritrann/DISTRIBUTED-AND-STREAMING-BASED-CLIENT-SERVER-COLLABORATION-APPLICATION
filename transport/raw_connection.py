#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
StreapRous Raw Connection Library
A library for handling TCP connections with raw sockets.
Based on raw_connection_server.py implementation.
Provides connection management, send/receive functionality using raw sockets.
"""

import socket
import struct
import sys
import threading
import time
import queue
from collections import namedtuple
import netifaces
import random
import platform
import subprocess

# Import streaprout packet dispatcher functions
from .streaprous_packet_dispatcher import (
    start_packet_dispatcher,
    stop_packet_dispatcher,
    get_packet_queue,
    remove_packet_queue,
    _packet_dispatcher_lock,
    _SYN_KEY,
)


# Connection structure 
# This structure holds connection and its state information
conn_struct = namedtuple('conn_struct', [
    'client_ip',
    'client_port',
    'server_ip',
    'server_port',
    'state',
    'server_seq',
    'client_seq',
    'expected_final_ack',
    'last_activity'
])


# Global table to manage multiple connection
# The mapping include {key: value} as { (client_ip, client_port): conn_struct }
connections = {}
connections_lock = threading.Lock()

# Management structure to serialize the 3-way handshake
# Each hand shake is manage by a unique ID client_key
# including client_ip client_port
handshake_lock = threading.Lock()
handshake_in_progress = {}


# Default raw port listener
DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_LISTEN_PORT = 22239
DEFAULT_INTERFACE_NAME = "lo0"

def register_keep_port_alive(listen_ip="0.0.0.0", listen_port=22239, retry_interval=10):
    """
    Periodically register and maintain TCP port.
    Retry registration whenever binding/listening fails.
    Never accept incoming connections.
    
    Args:
        listen_ip: IP address to bind to (default: "0.0.0.0")
        listen_port: Port to bind to (default: 22239)
        retry_interval: Seconds to wait before retrying after failure (default: 10)
    
    Returns:
        threading.Thread: The background thread running the port keep-alive
    """
    def _keep_alive():
        print(f"[Streap_raw]  Start port keep-alive thread for {listen_ip}:{listen_port}")
        attempt = 0
        while True:
            attempt += 1
            standard_sock = None

            try:
                print(f"[Streap_raw] register_keep_port_alive: Attempt #{attempt} - Create socket...")
                standard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                standard_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                print(f"[Streap_raw] register_keep_port_alive: Bind to {listen_ip}:{listen_port}...")
                standard_sock.bind((listen_ip, listen_port))
                
                print(f"[Streap_raw] register_keep_port_alive: Listen on port {listen_port}...")
                standard_sock.listen(0)  # No backlog, we won't accept connections
                print(f"[Streap_raw] register_keep_port_alive: Done port {listen_port} registration.")

                # Keep socket alive until an error occurs.
                while True:
                    time.sleep(3600)
            except Exception as e:
                print(f"[Streap_raw] register_keep_port_alive: Fail port registration with error {e}")
            finally:
                if standard_sock:
                    print(f"[Streap_raw] register_keep_port_alive: Close socket...")
                    standard_sock.close()

            print(f"[Streap_raw] register_keep_port_alive: Retry port registration in {retry_interval}s... (attempt #{attempt + 1})")
            time.sleep(retry_interval)
    
    print(f"[Streap_raw] register_keep_port_alive: Starting background thread for port {listen_port}")
    thread = threading.Thread(target=_keep_alive, daemon=True, name=f"port-keep-alive-{listen_port}")
    thread.start()
    print(f"[Streap_raw] register_keep_port_alive: Thread started (name={thread.name})")
    return thread


def checksum(msg):
    """Calculates a checksum and returns computed values.

    Args:
         msg message data
    """
    if len(msg) % 2 == 1:
        msg += b'\x00'
    s = 0
    for i in range(0, len(msg), 2):
        w = struct.unpack('!H', msg[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def build_tcp_packet(src_ip, dest_ip, src_port, dst_port, seq, ack_seq, syn=0, ack=0, fin=0, window=5840):
    """Stitches a structurally flawless 20-byte TCP header.

    Args:
         src_ip    Source IP address
         dest_ip   Destination IP address
         src_port  Source port
         dst_port  Destination port
         seq       Sequence number
         ack_seq   ACK for sequence
         syn=0     SYN flag
         ack=0     ACK flag
         fin=0     FIN flag
    """
    flags = (ack << 4) + (syn << 1) + fin
    offset_res = (5 << 4) + 0  # 20 bytes data offset (5 * 4)
    urg_ptr = 0
    draft_checksum = 0

    # Build a draft (20 byte) header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    
    # Build addressing-header
    address_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, len(tcp_header_temp)
    )
    
    # Calculate mathematical checksum integer
    tcp_checksum = checksum(address_header+ tcp_header_temp)
    
    # Build the final TCP packet
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )
    
    return tcp_header


def build_ip_header(src_ip, dest_ip, protocol, payload_len):
    """Builds a structurally flawless 20-byte IP header.

    Args:
         src_ip       Source IP address
         dest_ip      Destination IP address
         protocol     Protocol number
         payload_len  Payload length
    """
    version_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + payload_len  # IP header + payload

    # TODO: We draft with no-fragment package
    #       Full implementation must include fragment
    #       handling function
    identification = 0x1234
    flags_fragment = 0x4000
    flags_offset = 0 
    ttl = 64
    draft_checksum = 0
    
    # Build draft header with no checksum
    ip_header_temp = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, draft_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )
    
    # Calculate the checksum
    ip_checksum = checksum(ip_header_temp)
    
    # Build the final IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, ip_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )
    
    return ip_header


def send_tcp_data_segment(s, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, payload, window=5840):
    """Assembles and transmits a single TCP segment containing data payload.

    Args:
         src_ip       Source IP address
         dest_ip      Destination IP address
         src_port     Source port
         dst_port     Destination port
         seq          Sequence number
         ack_seq      ACK for sequence
         syn          SYN flag
         ack          ACK flag
         payload      Payload

    """

    # TODO: Hardcode for fast data pushing
    #       The setting PSH + ACK
    #       need to modify in full schema
    flags = 0x18
    offset_res = (5 << 4) + 0
    urg_ptr = 0
    draft_checksum = 0
    
    # Build draft header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    
    tcp_len = len(tcp_header_temp) + len(payload)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, tcp_len
    )

    # Calculate the checksum    
    tcp_checksum = checksum(pseudo + tcp_header_temp + payload)

    # Build the full TCP packet header    
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )

    # Build the full IP packet header     
    ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload))

    # Build the full packet header     
    full_packet = ip_header + tcp_header + payload

    # Send packet
    if DEBUG: print(f"[Streap_raw] send_tcp_data_segment: seq={seq}, ack_seq={ack_seq}, payload_len={len(payload)}, flags=0x{flags:02x}")
    if DEBUG: print(f"[Streap_raw] send_tcp_data_segment: TCP header seq={seq}, ack_seq={ack_seq}, flags=0x{flags:02x}")
    s.sendto(full_packet, (dest_ip, 0))
    
    return len(payload)


def clean_expired_connections(timeout=60):
    """Background thread to clean up stale or timed-out connections.

    Args:
         timeout Time expiration for clean-up working
    """
    while True:
        time.sleep(10)
        now = time.time()
        with connections_lock:
            expired = [k for k, session in connections.items() if now - session.last_activity > timeout]
            for k in expired:
                print(f"[Streap_raw] clean_expired_connections: Session [{k[0]}:{k[1]}] Connection timed out ({timeout}s inactivity). Remove connection.")
                del connections[k]


def create_raw_socket() -> socket.socket:
    """
    Create a raw socket for TCP protocol. The raw socket requires root privileges.
    It is raw with listen all packet for incoming port.
    
    Returns:
        Raw socket object
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # TODO: port listener need to be post-procesed later
        #       raw_socket ignore the transport protocol deatails

        print(f"[Streap_raw] Create raw socket binding for 0.0.0.0 listening")
        return sock
    except PermissionError:
        print("Error: Root privileges required (sudo).")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating raw socket: {e}")
        sys.exit(1)


def get_interface_ip(interface_name: str = None) -> str:
    """
    Get the IPv4 address of a network interface.
    
    Args:
        interface_name: Network interface name (e.g., 'enp0s8', 'eth0', 'en0')
                        If None, tries to find the default route interface.
    
    Returns:
        IPv4 address string
    """
    try:
        if interface_name:
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        else:
            # Try to get default route interface
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                iface = default_gateway[1]
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        pass
    
    # Fallback: try to get any non-loopback IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def accept(s: socket.socket, listen_ip: str, listen_port: int, interface_name: str = None) -> conn_struct:
    """
    Accept a new connection by performing the 3-way handshake using raw sockets.
    Returns a conn_struct tuple for the established connection.
    Handshakes are serialized to ensure only one 3-way handshake is processed at a time.
    
    Args:
        s: Raw socket
        listen_ip: Server IP to listen on (e.g., '0.0.0.0')
        listen_port: Server port to listen on
        interface_name: Network interface name for sending packets (optional)
    
    Returns:
        conn_struct: Established connection information
    """
    # Start packet dispatcher for this port
    start_packet_dispatcher(s, listen_port)
    
    # Get actual source IP for sending packets
    if listen_ip == "0.0.0.0":
        send_ip = get_interface_ip(interface_name)
        print(f"[Streap_raw] accept: listen_ip=0.0.0.0, using send_ip={send_ip} for outgoing packets")
    else:
        send_ip = listen_ip
    
    server_seq = 2000
    client_ip = None
    client_port = None

    print(f"[Streap_raw] accept: Waiting for incoming connections on {listen_ip}:{listen_port} (send_ip={send_ip})...")
    try:
        while True:
            if stop_accept:
                return None
            # Get packet from dispatcher queue (for SYN packets)
            syn_q = get_packet_queue(_SYN_KEY)
            try:
                packet, addr = syn_q.get(timeout=1.0)
                print(f"[Streap_raw] accept: Got packet from SYN queue")
            except queue.Empty:
                continue

            # Extract IP Header Length
            ihl = (packet[0] & 0x0F) * 4
            tcp_packet = packet[ihl:]
            
            if len(tcp_packet) < 20:
                continue

            # Unpack the received TCP header
            tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
            src_port, dest_port, pkt_seq, pkt_ack, flags = (
                tcph[0],
                tcph[1],
                tcph[2],
                tcph[3],
                tcph[5],
            )

            # Bypass non-listen port
            if dest_port != listen_port:
                continue

            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4

            # Build client_key from client IP and client port
            client_ip = socket.inet_ntoa(packet[12:16])
            client_port = src_port
            client_key = (client_ip, client_port)
            print(f"\n[Streap_raw] accept: Receiv packet from Client ({client_ip}:{client_port}) (Seq={pkt_seq}, SYN={syn_flag}, ACK={ack_flag})")

            # Create queue for each connection associated 
            # with tupple client_key=(client_ip, client_port)
            q = get_packet_queue(client_key)
            print(f"[Streap_raw] accept: Createet per-connection queue for {client_key}")
            with connections_lock:
                # Declare initialized session if not available
                if client_key not in connections:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="LISTEN",
                        server_seq=2000,
                        client_seq=0,
                        expected_final_ack=0,
                        last_activity=time.time()
                    )
                session = connections[client_key]

                        
            # Perform 3 handshake step
            # STEP 1: Obtain client SYN 
            if syn_flag == 1 and ack_flag == 0:
                print(f"\nHandshake1: Received SYN from Client ({client_ip}:{client_port}) (Seq={pkt_seq})")

                # Quick duplicate handshake check (fast, no heavy operations)
                with handshake_lock:
                    if handshake_in_progress.get(client_key, False):
                        print(f"[Streap_raw] accept: Handshake already in progress for {client_ip}:{client_port}, dropping SYN")
                        continue
                    handshake_in_progress[client_key] = True

                # STEP 2: Reply SYN-ACK immediately
                # Build TCP packet for SYN-ACK
                next_ack = pkt_seq + 1
                syn_ack_packet = build_tcp_packet(send_ip, client_ip, listen_port, client_port,
                                                  seq=server_seq, ack_seq=next_ack, syn=1, ack=1)
                ip_header = build_ip_header(send_ip, client_ip, socket.IPPROTO_TCP, len(syn_ack_packet))
                full_packet = ip_header + syn_ack_packet

                # Send SYN-ACK packet
                print(f"[Streap_raw] accept: Sending SYN-ACK to {client_ip}:{client_port} from {send_ip}:{listen_port}")
                print(f"[Streap_raw] accept: SYN-ACK packet size: {len(full_packet)} bytes (IP={len(ip_header)}, TCP={len(syn_ack_packet)})")
                bytes_sent = s.sendto(full_packet, (client_ip, 0))
                print(f"Handshake2: Sent SYN-ACK to Client (Seq={server_seq}, Ack={next_ack}, bytes_sent={bytes_sent})")

                # Register connection to the associated queue for each connection associated 
                # with tupple client_key=(client_ip, client_port)
                with connections_lock:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,  # Use actual sending IP
                        server_port=listen_port,
                        state="SYN_RCVD",
                        server_seq=server_seq,
                        client_seq=pkt_seq,
                        expected_final_ack=server_seq + 1,
                        last_activity=time.time()
                    )
                    session = connections[client_key]

                # STEP 3: Wait for client FIN-ACK
                # The final ACK will arrive on the per-connection queue, not the SYN queue
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    try:
                        packet, addr = q.get(timeout=0.5)
                        print(f"[Streap_raw] accept: Got packet from per-connection queue for {client_ip}:{client_port}")
                    except queue.Empty:
                        print(f"[Streap_raw] accept: Per-connection queue empty for {client_ip}:{client_port}, waiting...")
                        continue

                    # Extract IP Header Length
                    ihl = (packet[0] & 0x0F) * 4
                    tcp_packet = packet[ihl:]
                    
                    if len(tcp_packet) < 20:
                        continue

                    # Unpack the received TCP header
                    tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
                    src_port, dest_port, pkt_seq, pkt_ack, flags = (
                        tcph[0],
                        tcph[1],
                        tcph[2],
                        tcph[3],
                        tcph[5],
                    )

                    syn_flag = (flags & 0x02) >> 1
                    ack_flag = (flags & 0x10) >> 4
                    print(f"[Streap_raw] accept: Received packet in handshake wait - SYN={syn_flag}, ACK={ack_flag}, Seq={pkt_seq}, Ack={pkt_ack}")

                    # Check if this is the final ACK (ACK only, no SYN)
                    if syn_flag == 0 and ack_flag == 1:
                        print(f"[Streap_raw] accept: handshake3 Received FIN-ACK from Client (Seq={pkt_seq}, Ack={pkt_ack})")

                        with connections_lock:
                            if session.state != "SYN_RCVD":
                                print(f"[Streap_raw] accept: Non handshake state for {client_ip}:{client_port}")
                                break

                            # Update connection to ESTABLISHED
                            connections[client_key] = conn_struct(
                                client_ip=client_ip,
                                client_port=client_port,
                                server_ip=send_ip,
                                server_port=listen_port,
                                state="ESTABLISHED",
                                server_seq=pkt_ack,
                                client_seq=pkt_seq,
                                expected_final_ack=session.expected_final_ack,
                                last_activity=time.time()
                            )
                            session = connections[client_key]

                        # Clear handshake in progress flag
                        with handshake_lock:
                            handshake_in_progress[client_key] = False

                        print(f"[Streap_raw] Etablished handshak with connection: ({client_ip}:{client_port}) ESTABLISHED")
                        
                        # Return the established connection info
                        return session
                
                # Fallback of the handshake timeout
                print(f"[Streap_raw] Handshake timeout for {client_ip}:{client_port}")
                with handshake_lock:
                    handshake_in_progress[client_key] = False
                remove_packet_queue(client_key)
                with connections_lock:
                    connections.pop(client_key, None)
                continue

            # STEP 3 Exception handling: Capture FIN ACK on SYN queue ---
            if session.state == "SYN_RCVD" and syn_flag == 0 and ack_flag == 1:
                print(f"[Streap_raw] accept: handshake3 received Final ACK from Client on SYN queue (Seq={pkt_seq}, Ack={pkt_ack})")
                print(f"[Streap_raw] accept: Fallback - got final ACK on SYN queue for {client_ip}:{client_port}")

                with connections_lock:
                    if session.state != "SYN_RCVD":
                        print(f"[Streap_raw] accept: Non handshake state for {client_ip}:{client_port}")
                        continue

                    # Update connection to ESTABLISHED
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="ESTABLISHED",
                        server_seq=pkt_ack,
                        client_seq=pkt_seq,
                        expected_final_ack=session.expected_final_ack,
                        last_activity=time.time()
                    )
                    session = connections[client_key]

                # Clear handshake in progress flag
                with handshake_lock:
                    handshake_in_progress[client_key] = False

                print(f"[Streap_raw] Etablished handshak with connection: ({client_ip}:{client_port}) ESTABLISHED")
                
                # Return the established connection info
                return session

    except KeyboardInterrupt:
        print("\n[-] Server stopped.")
        # Clear handshake flags on interrupt
        with handshake_lock:
            handshake_in_progress.clear()
        raise


DEBUG = False
LOSS_RATE = 0.0
stop_accept = False
MSS = 536
RECV_WINDOW = 65535
MAX_RTO = 10.0
DEAD_TIME = 15.0
TIME_WAIT_TIME = 2.0

congestion_factory = None
tcb_table = {}
tcb_lock = threading.Lock()


def set_congestion_control(factory):
    global congestion_factory
    congestion_factory = factory


def setup_rst_block(port, enable=True):
    if platform.system() != "Linux":
        print("[Streap_raw] RST block only works on Linux")
        return
    if enable:
        action = "-A"
    else:
        action = "-D"
    subprocess.run(["iptables", action, "OUTPUT", "-p", "tcp", "--sport", str(port),
                    "--tcp-flags", "RST", "RST", "-j", "DROP"], capture_output=True)


class Reno:
    def __init__(self):
        self.cwnd = 2.0
        self.ssthresh = 64.0

    def on_packet_acked(self, acked_packets=1):
        for i in range(acked_packets):
            if self.cwnd < self.ssthresh:
                self.cwnd = self.cwnd + 1
            else:
                self.cwnd = self.cwnd + 1 / self.cwnd

    def on_loss(self):
        self.ssthresh = self.cwnd / 2
        if self.ssthresh < 2:
            self.ssthresh = 2
        self.cwnd = self.ssthresh

    def on_timeout(self):
        self.ssthresh = self.cwnd / 2
        if self.ssthresh < 2:
            self.ssthresh = 2
        self.cwnd = 1.0


class TCB:
    def __init__(self, s, conn_info):
        self.sock = s
        self.client_ip = conn_info.client_ip
        self.client_port = conn_info.client_port
        self.server_ip = conn_info.server_ip
        self.server_port = conn_info.server_port
        self.client_seq = conn_info.client_seq
        self.state = "ESTABLISHED"
        self.close_reason = ""
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.queue = get_packet_queue((self.client_ip, self.client_port))
        self.on_event = None
        if congestion_factory is None:
            self.cc = Reno()
        else:
            self.cc = congestion_factory()

        self.iss = conn_info.server_seq - 1
        self.irs = conn_info.client_seq - 1

        self.snd_una = 1
        self.snd_nxt = 1
        self.send_buffer = b""
        self.peer_window = RECV_WINDOW
        self.want_close = False
        self.fin_sent = False
        self.fin_seq = 0

        self.rto = 1.0
        self.srtt = None
        self.rttvar = None
        self.timer_start = None
        self.rtt_seq = None
        self.rtt_time = 0
        self.dup_acks = 0
        self.recover = None
        self.retransmissions = 0

        self.rcv_nxt = 1
        self.recv_buffer = b""
        self.out_of_order = {}
        self.peer_closed = False

        self.last_activity = time.time()
        self.time_wait_start = 0


def get_tcb(s, conn_info):
    key = (conn_info.client_ip, conn_info.client_port)
    with tcb_lock:
        if key in tcb_table:
            old = tcb_table[key]
            if old.client_seq == conn_info.client_seq:
                return old
        tcb = TCB(s, conn_info)
        tcb_table[key] = tcb
    t = threading.Thread(target=connection_worker, args=(tcb,))
    t.daemon = True
    t.start()
    return tcb


def connection_worker(tcb):
    key = (tcb.client_ip, tcb.client_port)
    while True:
        packet = None
        try:
            packet, addr = tcb.queue.get(timeout=0.02)
        except queue.Empty:
            packet = None
        if packet is not None and random.random() < LOSS_RATE:
            packet = None
        with tcb.lock:
            if packet is not None:
                handle_packet(tcb, packet)
            check_timer(tcb)
            if tcb.state == "CLOSED":
                break
    remove_packet_queue(key)
    with connections_lock:
        if key in connections:
            del connections[key]


def send_ack(tcb):
    if random.random() < LOSS_RATE:
        return
    window = RECV_WINDOW - len(tcb.recv_buffer)
    seq = (tcb.iss + tcb.snd_nxt) % 4294967296
    ack = (tcb.irs + tcb.rcv_nxt) % 4294967296
    tcp = build_tcp_packet(tcb.server_ip, tcb.client_ip, tcb.server_port, tcb.client_port,
                           seq, ack, ack=1, window=window)
    ip = build_ip_header(tcb.server_ip, tcb.client_ip, socket.IPPROTO_TCP, len(tcp))
    try:
        tcb.sock.sendto(ip + tcp, (tcb.client_ip, 0))
    except OSError as e:
        print("[Streap_raw] send ack error:", e)


def send_fin(tcb, rel_seq):
    if random.random() < LOSS_RATE:
        return
    window = RECV_WINDOW - len(tcb.recv_buffer)
    seq = (tcb.iss + rel_seq) % 4294967296
    ack = (tcb.irs + tcb.rcv_nxt) % 4294967296
    tcp = build_tcp_packet(tcb.server_ip, tcb.client_ip, tcb.server_port, tcb.client_port,
                           seq, ack, ack=1, fin=1, window=window)
    ip = build_ip_header(tcb.server_ip, tcb.client_ip, socket.IPPROTO_TCP, len(tcp))
    try:
        tcb.sock.sendto(ip + tcp, (tcb.client_ip, 0))
    except OSError as e:
        print("[Streap_raw] send fin error:", e)


def send_data(tcb, rel_seq, data):
    if random.random() < LOSS_RATE:
        return
    window = RECV_WINDOW - len(tcb.recv_buffer)
    seq = (tcb.iss + rel_seq) % 4294967296
    ack = (tcb.irs + tcb.rcv_nxt) % 4294967296
    try:
        send_tcp_data_segment(tcb.sock, tcb.server_ip, tcb.client_ip, tcb.server_port,
                              tcb.client_port, seq, ack, data, window=window)
    except OSError as e:
        print("[Streap_raw] send data error:", e)


def handle_packet(tcb, packet):
    ihl = (packet[0] & 0x0F) * 4
    total_len = struct.unpack('!H', packet[2:4])[0]
    tcp_packet = packet[ihl:total_len]
    if len(tcp_packet) < 20:
        return

    tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
    src_port = tcph[0]
    dest_port = tcph[1]
    pkt_seq = tcph[2]
    pkt_ack = tcph[3]
    tcp_header_len = (tcph[4] >> 4) * 4
    flags = tcph[5]
    window = tcph[6]
    payload = tcp_packet[tcp_header_len:]

    if dest_port != tcb.server_port or src_port != tcb.client_port:
        return
    if tcb.state == "CLOSED":
        return

    syn_flag = (flags & 0x02) >> 1
    ack_flag = (flags & 0x10) >> 4
    fin_flag = flags & 0x01
    rst_flag = (flags & 0x04) >> 2

    tcb.last_activity = time.time()

    if rst_flag == 1:
        close_tcb(tcb, "reset by peer")
        return
    if syn_flag == 1:
        send_ack(tcb)
        return
    if ack_flag == 0:
        return

    ack_number = (pkt_ack - tcb.iss) % 4294967296
    seq_number = (pkt_seq - tcb.irs) % 4294967296

    no_data = False
    if len(payload) == 0 and fin_flag == 0:
        no_data = True
    handle_ack(tcb, ack_number, window, no_data)

    if len(payload) > 0 or fin_flag == 1:
        handle_data(tcb, seq_number, payload, fin_flag)
    elif seq_number != tcb.rcv_nxt:
        send_ack(tcb)
    notify(tcb)


def handle_ack(tcb, ack_number, window, no_data):
    old_window = tcb.peer_window
    tcb.peer_window = window
    now = time.time()

    if ack_number > tcb.snd_nxt:
        return

    if ack_number > tcb.snd_una:
        acked = ack_number - tcb.snd_una
        tcb.send_buffer = tcb.send_buffer[acked:]
        tcb.snd_una = ack_number
        tcb.dup_acks = 0

        if tcb.rtt_seq is not None and ack_number > tcb.rtt_seq:
            update_rtt(tcb, now - tcb.rtt_time)
            tcb.rtt_seq = None
        elif tcb.srtt is not None:
            fix_rto(tcb)

        if tcb.recover is not None:
            if ack_number < tcb.recover:
                resend_first(tcb)
            else:
                tcb.recover = None
        else:
            packets = acked // MSS
            if packets < 1:
                packets = 1
            tcb.cc.on_packet_acked(packets)

        if tcb.snd_una < tcb.snd_nxt:
            tcb.timer_start = now
        else:
            tcb.timer_start = None

        if tcb.fin_sent and tcb.snd_una == tcb.fin_seq + 1:
            if tcb.state == "FIN_WAIT_1":
                tcb.state = "FIN_WAIT_2"
            elif tcb.state == "CLOSING":
                tcb.state = "TIME_WAIT"
                tcb.time_wait_start = now
                tcb.timer_start = None
            elif tcb.state == "LAST_ACK":
                close_tcb(tcb, "closed")
                return

    elif ack_number == tcb.snd_una and no_data and window == old_window:
        if window > 0 and tcb.snd_una < tcb.snd_nxt:
            tcb.dup_acks = tcb.dup_acks + 1
            if tcb.dup_acks == 3 and tcb.recover is None:
                tcb.recover = tcb.snd_nxt
                tcb.cc.on_loss()
                resend_first(tcb)

    send_more(tcb)


def update_rtt(tcb, sample):
    if tcb.srtt is None:
        tcb.srtt = sample
        tcb.rttvar = sample / 2
    else:
        tcb.rttvar = 0.75 * tcb.rttvar + 0.25 * abs(tcb.srtt - sample)
        tcb.srtt = 0.875 * tcb.srtt + 0.125 * sample
    fix_rto(tcb)


def fix_rto(tcb):
    tcb.rto = tcb.srtt + 4 * tcb.rttvar
    if tcb.rto < 0.2:
        tcb.rto = 0.2
    if tcb.rto > MAX_RTO:
        tcb.rto = MAX_RTO


def send_more(tcb):
    if tcb.state != "ESTABLISHED" and tcb.state != "CLOSE_WAIT":
        return
    now = time.time()

    cwnd_bytes = int(tcb.cc.cwnd) * MSS
    if cwnd_bytes < MSS:
        cwnd_bytes = MSS
    limit = tcb.peer_window
    if cwnd_bytes < limit:
        limit = cwnd_bytes

    while True:
        in_flight = tcb.snd_nxt - tcb.snd_una
        if in_flight >= len(tcb.send_buffer):
            break
        can_send = limit - in_flight
        if can_send <= 0:
            if tcb.peer_window == 0 and in_flight == 0:
                can_send = 1
            else:
                break
        size = MSS
        if can_send < size:
            size = can_send
        if len(tcb.send_buffer) - in_flight < size:
            size = len(tcb.send_buffer) - in_flight

        data = tcb.send_buffer[in_flight:in_flight + size]
        send_data(tcb, tcb.snd_nxt, data)
        if tcb.rtt_seq is None:
            tcb.rtt_seq = tcb.snd_nxt
            tcb.rtt_time = now
        if tcb.timer_start is None:
            tcb.timer_start = now
        tcb.snd_nxt = tcb.snd_nxt + size

    all_sent = False
    if tcb.snd_nxt - tcb.snd_una == len(tcb.send_buffer):
        all_sent = True
    if tcb.want_close and not tcb.fin_sent and all_sent:
        tcb.fin_seq = tcb.snd_nxt
        send_fin(tcb, tcb.snd_nxt)
        tcb.snd_nxt = tcb.snd_nxt + 1
        tcb.fin_sent = True
        if tcb.timer_start is None:
            tcb.timer_start = now
        if tcb.state == "ESTABLISHED":
            tcb.state = "FIN_WAIT_1"
        else:
            tcb.state = "LAST_ACK"


def resend_first(tcb):
    size = tcb.snd_nxt - tcb.snd_una
    if tcb.fin_sent:
        size = size - 1
    if size > MSS:
        size = MSS
    if size > 0:
        send_data(tcb, tcb.snd_una, tcb.send_buffer[:size])
    elif tcb.fin_sent:
        send_fin(tcb, tcb.fin_seq)
    else:
        return
    tcb.retransmissions = tcb.retransmissions + 1
    tcb.timer_start = time.time()
    tcb.rtt_seq = None


def handle_data(tcb, seq, data, fin_flag):
    fin_seq = seq + len(data)
    if tcb.peer_closed:
        data = b""

    if len(data) > 0 and seq < tcb.rcv_nxt:
        data = data[tcb.rcv_nxt - seq:]
        seq = tcb.rcv_nxt

    right_edge = tcb.rcv_nxt + RECV_WINDOW - len(tcb.recv_buffer)
    if seq + len(data) > right_edge:
        if right_edge > seq:
            data = data[:right_edge - seq]
        else:
            data = b""

    if len(data) > 0:
        if seq == tcb.rcv_nxt:
            tcb.recv_buffer = tcb.recv_buffer + data
            tcb.rcv_nxt = tcb.rcv_nxt + len(data)
            while tcb.rcv_nxt in tcb.out_of_order:
                more = tcb.out_of_order.pop(tcb.rcv_nxt)
                tcb.recv_buffer = tcb.recv_buffer + more
                tcb.rcv_nxt = tcb.rcv_nxt + len(more)
            for old_seq in list(tcb.out_of_order.keys()):
                if old_seq < tcb.rcv_nxt:
                    del tcb.out_of_order[old_seq]
        else:
            tcb.out_of_order[seq] = data

    if fin_flag == 1 and fin_seq == tcb.rcv_nxt and not tcb.peer_closed:
        tcb.rcv_nxt = tcb.rcv_nxt + 1
        tcb.peer_closed = True
        if tcb.state == "ESTABLISHED":
            tcb.state = "CLOSE_WAIT"
        elif tcb.state == "FIN_WAIT_1":
            tcb.state = "CLOSING"
        elif tcb.state == "FIN_WAIT_2":
            tcb.state = "TIME_WAIT"
            tcb.time_wait_start = time.time()
            tcb.timer_start = None

    send_ack(tcb)


def check_timer(tcb):
    now = time.time()
    if tcb.state == "CLOSED":
        return
    if tcb.state == "TIME_WAIT":
        if now - tcb.time_wait_start > TIME_WAIT_TIME:
            close_tcb(tcb, "closed")
        return
    if tcb.state == "FIN_WAIT_2" and now - tcb.last_activity > DEAD_TIME:
        close_tcb(tcb, "peer not responding")
        return
    if tcb.timer_start is None:
        return
    if now - tcb.timer_start < tcb.rto:
        return

    if now - tcb.last_activity > DEAD_TIME:
        close_tcb(tcb, "peer not responding")
        return

    tcb.rto = tcb.rto * 2
    if tcb.rto > MAX_RTO:
        tcb.rto = MAX_RTO
    if tcb.peer_window > 0:
        if hasattr(tcb.cc, "on_timeout"):
            tcb.cc.on_timeout()
        else:
            tcb.cc.on_loss()
    tcb.recover = tcb.snd_nxt
    tcb.dup_acks = 0
    resend_first(tcb)


def close_tcb(tcb, reason):
    if tcb.state == "CLOSED":
        return
    tcb.state = "CLOSED"
    tcb.close_reason = reason
    notify(tcb)


def notify(tcb):
    tcb.cond.notify_all()
    if tcb.on_event is not None:
        tcb.on_event()


def is_readable(tcb):
    if len(tcb.recv_buffer) > 0:
        return True
    if tcb.peer_closed:
        return True
    if tcb.state == "CLOSED":
        return True
    return False


def get_status(conn_info):
    tcb = conn_info
    with tcb.lock:
        srtt_ms = None
        if tcb.srtt is not None:
            srtt_ms = round(tcb.srtt * 1000, 2)
        return {
            "client": tcb.client_ip + ":" + str(tcb.client_port),
            "state": tcb.state,
            "cwnd": round(tcb.cc.cwnd, 2),
            "ssthresh": round(tcb.cc.ssthresh, 2),
            "peer_window": tcb.peer_window,
            "bytes_in_flight": tcb.snd_nxt - tcb.snd_una,
            "srtt_ms": srtt_ms,
            "rto_ms": round(tcb.rto * 1000),
            "retransmissions": tcb.retransmissions,
        }


def run_conn_recv(s: socket.socket, conn_info: conn_struct, size: int = 65536) -> bytes:
    """
    Receive data on an established connection using raw sockets.
    This function handles incoming packets for a specific connection by reading
    from the packet dispatcher's per-connection queue.
    
    Args:
        s: raw socket
        conn_info: conn_struct tuple for the connection
    
    Returns:
        bytes: The received data payload, or empty bytes if connection closed
    """
    tcb = get_tcb(s, conn_info)
    with tcb.lock:
        while not is_readable(tcb):
            tcb.cond.wait(0.5)
        if len(tcb.recv_buffer) == 0:
            return b""
        free_before = RECV_WINDOW - len(tcb.recv_buffer)
        data = tcb.recv_buffer[:size]
        tcb.recv_buffer = tcb.recv_buffer[size:]
        if free_before < MSS:
            if tcb.state == "ESTABLISHED" or tcb.state == "FIN_WAIT_1" or tcb.state == "FIN_WAIT_2":
                send_ack(tcb)
        notify(tcb)
        return data


def run_conn_send(s: socket.socket, conn_info: conn_struct, payload: bytes) -> int:
    """
    Send data on an established connection using raw sockets.
    
    Args:
        s: Raw socket
        conn_info: conn_struct tuple for the connection
        payload: Bytes payload to send
    
    Returns:
        int: Number of bytes sent, or -1 on error
    """
    tcb = get_tcb(s, conn_info)
    with tcb.lock:
        if tcb.state != "ESTABLISHED" and tcb.state != "CLOSE_WAIT":
            return -1
        if tcb.want_close:
            return -1
        tcb.send_buffer = tcb.send_buffer + payload
        send_more(tcb)
        return len(payload)


def close_connection(s: socket.socket, conn_info: conn_struct):
    """Close a specific connection by sending FIN and removing from connection table."""
    tcb = get_tcb(s, conn_info)
    with tcb.lock:
        if tcb.state == "ESTABLISHED" or tcb.state == "CLOSE_WAIT":
            tcb.want_close = True
            send_more(tcb)


def close_all_connections():
    """Close all connections and clean up."""
    with connections_lock:
        connections.clear()
