"""Start the chat server (needs Linux/WSL and root because of the raw socket).

    sudo python3 run_server.py --host 127.0.0.1 --port 9000
"""

import runpy

if __name__ == "__main__":
    runpy.run_module("server.server", run_name="__main__", alter_sys=True)
