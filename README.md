# Distributed and Streaming-based Client-Server Collaboration Application

CO3094 Network Application, Assignment 1. A self-hosted chat and file-sharing
app for a LAN: login, live list of online users, broadcast and private
messages, reliable file transfer, AES-GCM encryption, a CLI client and a web
UI that uses only client-side JavaScript.

```
 browser (HTML + JS)                         terminal
        | HTTP/JSON (fetch, polling)              |
   ui/gateway.py  ── uses ──┐            run_client.py (CLI)
                            v                     |
                    client/client.py  (ChatClient: login, chat, files, heartbeat)
                            |  4-byte length + AES-256-GCM encrypted JSON
                            v
                 server/server.py  (selectors event loop, routing, auth)
                            |
                 transport/raw_socket.py  (socket-like wrapper, one worker per client)
                            |
      our transport design (design draft, 3 parts):
        segment.py       packet structure + checksum          (reliability)
        reliability.py   seq/ACK, sliding window, timer, resend (reliability)
        flow_control.py  64 KB circular receive buffer, rwnd   (flow control)
        congestion.py    Multi-Tier AIMD, 3 congestion tiers  (congestion control)
                            v
   transport/streaprous_raw_connection.py + streaprous_packet_dispatcher.py
                 (teacher's StreapRous files, used unchanged and only to
                  connect: raw socket, 3-way handshake, per-client queues)
```

## 1. Requirements

* Linux or **WSL (Ubuntu)** on Windows. The server opens a raw socket, so it
  must run as **root** (`sudo`). Clients and the web gateway do not need root.
* Python 3.9 or newer.
* Packages: `iptables`, `cryptography`, `netifaces`.

Install once (Ubuntu / WSL):

```bash
sudo apt update
sudo apt install -y python3 iptables python3-cryptography python3-netifaces
```

(or `pip install -r requirements.txt` inside a virtual environment).

Get the code and go to the project folder, for example on WSL:

```bash
cd /mnt/d/tri/mangmaytinh/Assignment
```

## 2. Run the server

```bash
sudo python3 run_server.py --host 127.0.0.1 --port 9000
```

* `--host` must be a real IP of this machine, **not 0.0.0.0**. Use
  `127.0.0.1` when every client runs on the same machine, or the machine's LAN
  IP (see `ip addr`) when clients come from other machines.
* Stop it with **Ctrl+C**. That also removes the iptables rule the server adds
  (it drops the kernel's RST packets for the server port).

## 3. Connect clients

### Option A: command line (one terminal per user)

```bash
python3 run_client.py --host 127.0.0.1 --port 9000 --user tri_demo
python3 run_client.py --host 127.0.0.1 --port 9000 --user nam_demo
```

The password is asked on the terminal. Commands:

| Command | What it does |
| --- | --- |
| `hello all` | send to everyone |
| `/msg nam_demo hi` | private message |
| `/file nam_demo ./report.pdf` | send a file (saved in `downloads/<user>/`) |
| `/users` | online users with IP and port |
| `/status` | connection state and counters |
| `/quit` | leave |

### Option B: web UI

```bash
python3 run_gateway.py --port 8080
```

Open <http://127.0.0.1:8080/> in a browser. The gateway listens on all
interfaces (`0.0.0.0`) so a browser on Windows can reach it inside WSL; if
`127.0.0.1` still does not work, use the WSL address from `hostname -I`. Log in with server `127.0.0.1`, port `9000`. Open a second tab or
a private window to log in as another user. Click a user on the left to send a
private message or a file; progress bars are on the right.

### Demo accounts

| Username | Password |
| --- | --- |
| tri_demo, nam_demo, an_demo, binh_demo | 123456 |
| user01 ... user20 (for the 20-client test) | 123456 |

Accounts are in `server/data/users.json` (PBKDF2-SHA256 hashes with salt).
To add one:

```bash
python3 -c "from server.auth import create_user_record as c; import json; print(json.dumps(c('mypassword')))"
```

and paste the result under a new username in `users.json`.

## 4. Run the tests

```bash
sudo python3 -m unittest discover tests -v
```

| File | What it checks | Needs root |
| --- | --- | --- |
| `test_framing.py` | 4-byte length framing | no |
| `test_auth.py` | password hashing, users file | no |
| `test_crypto.py` | AES-GCM round trip, tamper and wrong-key rejection | no |
| `test_client.py` | file reassembly, SHA-256 check, missing chunks | no |
| `test_transport.py` | checksum, 64 KB buffer and rwnd, the 3 congestion tiers, ordering, resend, 20 % loss | no |
| `test_server.py` | real server process: login, broadcast, unicast, file relay, encryption, **20 concurrent clients**, heartbeat timeout | yes |

Without root the server tests are skipped. To test under packet loss, set
`LOSS_RATE = 0.1` in `transport/raw_socket.py`, run the tests again, then set
it back to `0.0`.

## 5. Protocol summary

Every message is `4-byte big-endian length | AES-256-GCM(nonce 12 B | JSON | tag 16 B)`.

| Type | Direction | Fields |
| --- | --- | --- |
| `HELLO` / `HELLO_ACK` | C→S / S→C | `conn_id` |
| `LOGIN` | C→S | `username`, `password` |
| `LOGIN_OK` / `LOGIN_FAIL` | S→C | `session_id` / `reason` |
| `USER_LIST` | both | `users`, `peers` (`username`, `ip`, `port`) |
| `JOIN` / `LEAVE` | S→C | `username` |
| `MSG` | both | `to` (`*` = everyone), `text`; the server adds `from`, `ts` |
| `MSG_ACK` | S→C | `to`, `ts` |
| `FILE_META` | relayed | `to`, `file_id`, `name`, `size`, `chunks`, `sha256` |
| `FILE_CHUNK` | relayed | `to`, `file_id`, `index`, `data` (base64 of 32 KB) |
| `FILE_END` | relayed | `to`, `file_id` |
| `HEARTBEAT` | C→S | every 5 s; silent clients are closed after 15 s |
| `BYE` | C→S | clean logout |
| `ERROR` | S→C | `reason` |

Settings (ports, heartbeat, chunk size, shared secret) are in `config.py`.

## 6. Troubleshooting

| Problem | Fix |
| --- | --- |
| `No such file or directory: 'iptables'` | `sudo apt install -y iptables` |
| `Root privileges required (sudo)` | start the server with `sudo` |
| `No module named 'netifaces'` / `'cryptography'` | `sudo apt install -y python3-netifaces python3-cryptography` |
| client cannot connect | server `--host` must be the IP the client uses (not `0.0.0.0`) |
| `cannot decrypt message` | client and server must have the same `SHARED_SECRET` in `config.py` |
| other machines cannot reach a server in WSL2 | WSL2 is behind NAT: run the server on a Linux machine or a VM with bridged networking |
