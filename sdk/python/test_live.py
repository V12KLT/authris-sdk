import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from authv4 import AuthError, Client

BASE = "http://127.0.0.1:18081"
TOKEN = None


def api(method, path, payload=None):
    body = json.dumps(payload or {}).encode()
    request = urllib.request.Request(
        BASE + path, data=body if method != "GET" else None,
        headers={"Content-Type": "application/json"}, method=method
    )
    if TOKEN:
        request.add_header("Authorization", "Bearer " + TOKEN)
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read().decode()
        try:
            return response.status, json.loads(raw)
        except ValueError:
            return response.status, raw


def check(name, condition):
    print(("PASS " if condition else "FAIL ") + name)
    if not condition:
        raise SystemExit("live check failed: " + name)


class Stub(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        Stub.received = self.rfile.read(length)
        Stub.hmac = self.headers.get("X-KeyAuth-HMAC")
        payload = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main():
    tmp = tempfile.mkdtemp(prefix="authv4-live-")
    db_path = os.path.join(tmp, "live.db")
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    binary = os.path.join(tmp, "server.exe")
    build = subprocess.run(
        ["go", "build", "-o", binary, "./cmd/server"],
        cwd=os.path.join(repo, "backend"), capture_output=True, text=True
    )
    if build.returncode != 0:
        print(build.stderr)
        raise SystemExit("go build failed")
    env = dict(os.environ)
    env["AUTHV4_DB"] = db_path
    env["AUTHV4_ADDR"] = "127.0.0.1:18081"
    env["AUTHV4_ALLOW_PRIVATE_WEBHOOKS"] = "1"
    server = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE + "/api/public/status", timeout=2).read()
                break
            except Exception:
                time.sleep(0.2)
        global TOKEN
        status, _ = api("POST", "/api/auth/register", {"username": "sdkuser", "password": "DemoPass123!", "tos_agreed": True, "email": "sdkuser@example.com"})
        check("register", status == 200)
        status, logged = api("POST", "/api/auth/login", {"username": "sdkuser", "password": "DemoPass123!"})
        check("login", status == 200)
        TOKEN = logged["token"]
        status, created = api("POST", "/api/dashboard/projects", {"name": "sdkproj"})
        check("project", status == 200)
        pid = created["project_id"]
        status, added = api("POST", "/api/dashboard/projects/" + pid + "/keys", {"duration": "1 day"})
        check("key", status == 200)
        key = added["key"]
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE accounts SET tier = 'silver' WHERE username = 'sdkuser'")
        conn.commit()
        conn.close()
        status, _ = api("POST", "/api/dashboard/projects/" + pid + "/variables", {"name": "offset", "value": "0x10"})
        check("variable set", status == 200)
        secret = b"sdk-file-secret-bytes"
        status, _ = api("POST", "/api/dashboard/projects/" + pid + "/files", {
            "name": "app.bin", "data": base64.b64encode(secret).decode(),
        })
        check("file upload", status == 200)
        stub = HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=stub.serve_forever, daemon=True).start()
        hook_url = "http://127.0.0.1:%d/hook" % stub.server_port
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO project_webhooks (project_id, webhook_id, name, url, secret_key, created_at) VALUES (?, 'wh1', 'orders', ?, 'topsecret', ?)",
            (pid, hook_url, int(time.time()))
        )
        conn.commit()
        conn.close()
        status, _ = api("POST", "/api/dashboard/projects/" + pid + "/tables", {"name": "config", "columns": ["offset", "label"]})
        check("table create", status == 200)

        app = Client(project_id=pid, base_url=BASE)
        app.init()
        check("sdk init", bool(app.server_key))
        licensed = app.license(key=key, hwid="5D-1C-01")
        check("sdk license", licensed["remaining"] > 80000)
        check("sdk heartbeat", app.heartbeat() > 80000)
        info = app.info()
        check("sdk info", info["status"] == "active")
        check("sdk variable", app.variable("offset") == "0x10")
        check("sdk variables", app.variable()["offset"] == "0x10")
        try:
            check("sdk file", app.file("app.bin") == secret)
        except AuthError as exc:
            if "cryptography" not in str(exc):
                raise
            print("SKIP sdk file (cryptography package not installed)")
        hooked = app.webhook("orders", data="ping")
        check("sdk webhook", hooked["status"] == 200 and Stub.hmac)
        check("sdk table add", app.table("config", "add_row", data={"offset": "0x20"})["ok"])
        rows = app.table("config", "get_rows")
        check("sdk table rows", len(rows["rows"]) == 1)

        bad = Client(project_id=pid, base_url=BASE)
        try:
            bad.license(key="ZZZZ-9999-ZZZZ-9999", hwid="5D-1C-01")
            check("bad key rejected", False)
        except AuthError as exc:
            check("bad key rejected", "Invalid key" in str(exc))
        mismatch = Client(project_id=pid, base_url=BASE)
        try:
            mismatch.license(key=key, hwid="AA-BB-CC")
            check("second device limited", False)
        except AuthError as exc:
            check("second device limited", "Session limit reached" in str(exc))
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE project_keys SET max_sessions = 5 WHERE project_id = ?", (pid,))
        conn.commit()
        conn.close()
        mismatch = Client(project_id=pid, base_url=BASE)
        try:
            mismatch.license(key=key, hwid="AA-BB-CC")
            check("hwid mismatch rejected", False)
        except AuthError as exc:
            check("hwid mismatch rejected", "HWID Mismatch" in str(exc))
        print("ALL LIVE CHECKS PASSED")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    main()
