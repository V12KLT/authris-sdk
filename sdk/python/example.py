import sys
import time

sys.path.insert(0, "sdk/python")

from authv4 import AuthError, Client

app = Client(project_id="PASTE_PROJECT_ID", base_url="http://127.0.0.1:8080")

try:
    app.init()
    app.license(key="XXXX-XXXX-XXXX-XXXX")
    print("licensed, remaining:", app.remaining)
    while True:
        time.sleep(60)
        print("heartbeat, remaining:", app.heartbeat())
except AuthError as exc:
    print("auth failed:", exc)
