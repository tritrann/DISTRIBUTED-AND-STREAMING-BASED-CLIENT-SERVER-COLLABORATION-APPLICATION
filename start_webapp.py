"""Start the web application."""

import argparse

from apps.webapp import create_webapp

PORT = 2026


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="WebApp",
        description="Start the web application",
    )
    parser.add_argument("--server-ip", default="0.0.0.0")
    parser.add_argument("--server-port", type=int, default=PORT)

    args = parser.parse_args()
    create_webapp(args.server_ip, args.server_port)
