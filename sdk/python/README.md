# authv4 (Python)

Authris license client for Python 3.9+. Standard library only —
no dependencies unless you download encrypted files.

```sh
pip install authv4
# with encrypted file downloads:
pip install "authv4[files]"
```

```python
import time
from authv4 import AuthError, Client

app = Client(project_id="PASTE_PROJECT_ID", base_url="https://your-server")

try:
    app.init()
    app.license(key="XXXX-XXXX-XXXX-XXXX")
    print("licensed, remaining:", app.remaining)
    while True:
        time.sleep(60)
        print("heartbeat, remaining:", app.heartbeat())
except AuthError as exc:
    print("auth failed:", exc)
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
