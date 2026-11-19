"""Start the HTTP gateway for the web UI, then open http://127.0.0.1:8080/

    python3 run_gateway.py --port 8080
"""

from ui.gateway import main

if __name__ == "__main__":
    main()
