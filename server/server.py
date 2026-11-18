import socket
import errno
import time
import selectors
import sys
import json
import argparse

from common.framing import MAX_MESSAGE_SIZE, pack, split


class Server:
    def __init__ (self, server_bind_host, server_tcp_port, server_udp_port):
        self.server_bind_host = server_bind_host
        self.server_TCP_port = server_tcp_port
        self.server_UDP_port = server_udp_port
        self.client_dict = {}
        self.connection_id = 0
        self.running = True
        self.message_handler = {
            "HELLO" : self._on_hello
        }
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
                        
        self.sel.register(self.server_TCP_socket, selectors.EVENT_READ, data= "LISTENER")       
                
                
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
        conn_id = client["conn_id"]
        
        print(f"[JOIN] conn#{conn_id} {client_address} (total: {len(self.client_dict)})")
                
    def run(self):
        while self.running:
            event = self.sel.select(1.0)
            for key, mask in event:
                if key.data == "LISTENER":
                    try:
                        client_socket, client_address = self.server_TCP_socket.accept()
                    except BlockingIOError:
                        continue
                    self.add_client_to_list(client_socket, client_address)
                else :
                    self._handle_client_read(key)
                    
    def close_client(self, client_socket):
        client = self.client_dict.get(client_socket)
        if client is None:
            return
        else:
            conn_id = client["conn_id"]
            username = client["username"]
            client_address = client["address"]
            try:
                self.sel.unregister(client_socket)
            except KeyError:
                pass
        
            try:
                client_socket.close()
            except OSError:
                pass
            self.client_dict.pop(client_socket, None)
            print(f"[LEAVE] conn#{conn_id} {username} {client_address} (total: {len(self.client_dict)}) ")
            
    def _handle_client_read(self, key: selectors.SelectorKey):
        client_socket = key.fileobj
        client = key.data
        try:
            request = client_socket.recv(4096)
        except BlockingIOError:
            return
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            self.close_client(client_socket)
            return
        if request == b"" :
            self.close_client(client_socket)
            return
        #TODO (heartbeat) : update last_seen here
        client["last_seen"] = time.monotonic()
        client["recv_buffer"] += request
        buffer = client["recv_buffer"] 
        try:
            message_list, remain = split(buffer)
        except ValueError:
            self.close_client(client_socket)
            return
        client["recv_buffer"] = remain
        for message in message_list:
            self._handle_message(client, message)
            if self.client_dict.get(client_socket) is None:
                return
            
        
    def _handle_message(self, client: dict, message:bytes):
        try:
            data = message.decode("utf-8")
            data = json.loads(data)
        except ValueError:
            self._send_error(client, "invalid JSON")
            return
        if not isinstance(data, dict):
            self._send_error(client,"payload must be a JSON object" )
            return
        
        message_type = data.get("type")
        if not isinstance(message_type, str):
            self._send_error(client, "missing or invalid type")
            return
        
        handler = self.message_handler.get(message_type)
        if handler is None:
            self._send_error(client, f"unknown type: {message_type}")
            return
        
        handler(client, data)
        
            
    def _send(self, client: dict, message_dict: dict):
        if self.client_dict.get(client["socket"]) is None:
            return False
        message = json.dumps(message_dict).encode("utf-8")
        message = pack(message)
        try:
            client["socket"].sendall(message)
            return True
        except OSError:
            self.close_client(client["socket"])
            return False
        
    def _send_error(self, client: dict, reason:str): 
        conn_id = client["conn_id"]
        print(f"[ERROR] conn#{conn_id} {reason}")
        self._send(client, {"type": "ERROR", "reason": reason})
    
    def _on_hello(self, client : dict, data):
        self._send(client, {"type": "HELLO_ACK", "conn_id": client["conn_id"]})
        conn_id = client["conn_id"]
        print(f"[HELLO] conn#{conn_id}")
    
    def shutdown(self):
        self.running = False
        for client_socket in list(self.client_dict):
            self.close_client(client_socket)
        self.sel.unregister(self.server_TCP_socket)
        self.server_TCP_socket.close()
        self.sel.close()
        print("Server stopped")
        
            
    
if __name__ == "__main__":
    server = Server("0.0.0.0", 9000, 9001)
    try:
        server.start()
        server.run()
    except KeyboardInterrupt:
        server.shutdown()
    except OSError:
        sys.exit(1)