import json

from daemon import StreapRous

app = StreapRous()


@app.route('/login', methods=['POST'])
def login(headers="guest", body="anonymous"):
    """Receive a login request from the web page."""
    print("[WebApp] Login request received")

    data = {"message": "Login request received."}

    json_str = json.dumps(data)
    return json_str.encode("utf-8")


def create_webapp(ip, port):
    app.prepare_address(ip, port)
    app.run()
