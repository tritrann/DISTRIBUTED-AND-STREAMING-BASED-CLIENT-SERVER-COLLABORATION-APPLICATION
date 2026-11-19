SERVER_HOST = "0.0.0.0"
SERVER_TCP_PORT = 9000
SERVER_UDP_PORT = 9001
MAX_MESSAGE_SIZE = 1024 * 1024
MAX_USERNAME_SIZE = 32
# Server closes a client that sends nothing for this many seconds (0 = off).
# The client sends {"type": "HEARTBEAT"} every HEARTBEAT_INTERVAL seconds.
HEARTBEAT_TIMEOUT = 15
HEARTBEAT_INTERVAL = 5
MAX_TEXT_LENGTH = 2000

# Security layer (Step 8): every message between a client and the server is
# encrypted with AES-256-GCM. Both sides build the same key from this shared
# secret with PBKDF2, so change SHARED_SECRET for your own team.
ENCRYPTION = True
SHARED_SECRET = "co3094-network-assignment-1"
KEY_SALT = "5f3c9a1e7b2d4c6e8a0f1b3d5e7c9a2b"   # 16 bytes, hex
KEY_ITERATIONS = 200_000

# File transfer: raw bytes per FILE_CHUNK (sent as base64 inside the JSON)
FILE_CHUNK_SIZE = 32 * 1024
DOWNLOAD_DIR = "downloads"

# HTTP gateway for the web UI (Step 9)
# 0.0.0.0 so the browser on Windows can reach a gateway running inside WSL
GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 8080
