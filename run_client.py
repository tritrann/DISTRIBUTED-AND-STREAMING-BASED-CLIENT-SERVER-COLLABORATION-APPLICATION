"""Command-line client.

    python3 run_client.py --host 127.0.0.1 --port 9000 --user tri_demo

Commands (type /help):
    <text>                   send to everyone
    /msg <user> <text>       private message
    /file <user> <path>      send a file
    /users                   who is online (with IP and port)
    /status                  connection status and counters
    /quit                    leave
"""

import argparse
import getpass
import os
import sys
import time

import config
from client.client import ChatClient

HELP = __doc__.split("Commands (type /help):")[1]


def now():
    return time.strftime("%H:%M:%S")


def show(event):
    kind = event["type"]
    if kind == "message":
        where = "" if event["to"] == "*" else " (private)"
        print(f"[{now()}] {event['from']}{where}: {event['text']}")
    elif kind == "join":
        print(f"[{now()}] * {event['username']} joined")
    elif kind == "leave":
        print(f"[{now()}] * {event['username']} left")
    elif kind == "users":
        print(f"[{now()}] online: {', '.join(event['users'])}")
    elif kind == "error":
        print(f"[{now()}] ! {event['reason']}")
    elif kind == "status":
        print(f"[{now()}] {event['text']}")
    elif kind == "disconnected":
        print(f"[{now()}] disconnected: {event['reason']}")
    elif kind == "file_start":
        verb = "sending" if event["direction"] == "send" else "receiving"
        print(f"[{now()}] {verb} '{event['name']}' ({event['size']} bytes) {'to' if verb == 'sending' else 'from'} {event['peer']}")
    elif kind == "file_progress":
        size = event["size"] or 1
        percent = event["done"] * 100 // size
        bar = "#" * (percent // 5) + "-" * (20 - percent // 5)
        print(f"\r  [{bar}] {percent:3d}%", end="", flush=True)
        if event["done"] >= event["size"]:
            print()
    elif kind == "file_done":
        if not event["ok"]:
            print(f"[{now()}] ! file transfer failed: {event['reason']}")
        elif event["direction"] == "receive":
            print(f"[{now()}] file saved to {event['path']}")
        else:
            print(f"[{now()}] file sent")


def main():
    parser = argparse.ArgumentParser(description="Chat client (CLI)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=config.SERVER_TCP_PORT)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", help="asked on the terminal if not given")
    args = parser.parse_args()
    password = args.password or getpass.getpass("password: ")

    client = ChatClient(on_event=show)
    try:
        client.connect(args.host, args.port)
    except OSError as err:
        print(f"cannot connect to {args.host}:{args.port}: {err}")
        return 1
    ok, reason = client.login(args.user, password)
    if not ok:
        print(f"login failed: {reason}")
        client.close()
        return 1
    print(f"logged in as {args.user}. Type /help for commands.")

    try:
        while client.connected:
            line = input().strip()
            if not line:
                continue
            try:
                if not line.startswith("/"):
                    client.send_text("*", line)
                elif line == "/help":
                    print(HELP)
                elif line == "/quit":
                    break
                elif line == "/users":
                    for p in client.peers:
                        print(f"  {p['username']:<16} {p['ip']}:{p['port']}")
                elif line == "/status":
                    state = "connected" if client.connected else "disconnected"
                    print(f"  {state} to {client.server[0]}:{client.server[1]} as {client.username}")
                    print(f"  messages sent {client.stats['sent']}, received {client.stats['received']}")
                    print(f"  bytes sent {client.stats['bytes_sent']}, received {client.stats['bytes_received']}")
                elif line.startswith("/msg "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        print("usage: /msg <user> <text>")
                    else:
                        client.send_text(parts[1], parts[2])
                elif line.startswith("/file "):
                    parts = line.split(" ", 2)
                    if len(parts) < 3 or not os.path.isfile(parts[2]):
                        print("usage: /file <user> <path to an existing file>")
                    else:
                        client.send_file_path(parts[1], parts[2])
                else:
                    print("unknown command, type /help")
            except OSError as err:
                print(f"! {err}")
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
