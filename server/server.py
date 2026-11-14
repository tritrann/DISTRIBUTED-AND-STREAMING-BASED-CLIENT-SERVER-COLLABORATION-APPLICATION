import socket
import errno
import time
import selectors
import argparse


class Server:
    def __init__ (self, server_bind_host, server_tcp_port, server_udp_port):
        self.server_bind_host = server_bind_host
        self.server_TCP_port = server_tcp_port
        self.server_UDP_port = server_udp_port
        self.client_dict = {}
        self.connection_id = 0
        self.sel = selectors.DefaultSelector()
        
        
    def start(self):
        self.server_TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_TCP_socket.setblocking(False)
        try:
            self.server_TCP_socket.bind((self.server_bind_host, self.server_TCP_port))
            self.server_TCP_socket.listen(50)
            print(f"[OK] Server is running at {self.server_bind_host}:{self.server_TCP_port} ... ")
        except OSError as err:
            if err.errno in (errno.EADDRINUSE, errno.WSAEADDRINUSE):
                print(f"[ERROR] Port {self.server_TCP_port} is already in use by another process!")
            elif err.errno in (errno.EADDRNOTAVAIL, errno.WSAEADDRNOTAVAIL):
                print(f"[ERROR] IP address {self.server_bind_host} does not exist on this machine!")
            elif err.errno in (errno.EACCES, errno.WSAEACCES):
                print(f"[ERROR] Permission denied (Admin/Root required) to bind port {self.server_TCP_port}!")
            else:
                print(f"[SYSTEM ERROR] Failed to bind: {err}")
            self.server_TCP_socket.close()
            raise
                        
        while True:
            try:
                client_socket, client_address = self.server_TCP_socket.accept()
                self.add_client_to_list(client_socket, client_address)
                print(f"{client_socket}")
                print(f"{client_address}")
            except BlockingIOError:
                print("No client connected yet...")
                time.sleep(1)        
                
                
    def add_client_to_list(self, client_socket, client_address):
        self.connection_id += 1
        client = {
            "socket"       : client_socket,
            "address"      : client_address,
            "conn_id"      : self.connection_id,
            "state"        : "CONNECTED",
            "recv_buffer"  : b"",
            "connected_at" : time.time(),
            "last_seen"    : time.monotonic(),
            "username"     : None,
            "session_id"   : None,
        }
        client_socket.setblocking(False)
        self.client_dict[client_socket] = client
        self.sel.register(client_socket, selectors.EVENT_READ, data=client)
            
        
