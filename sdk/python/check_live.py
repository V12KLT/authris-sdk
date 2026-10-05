import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from authv4 import AuthError, Client

BASE = os.environ["AUTHV4_BASE"]
PID = os.environ["AUTHV4_PID"]
KEY = os.environ["AUTHV4_KEY"]
KEY2 = os.environ["AUTHV4_KEY2"]
HWID = os.environ["AUTHV4_HWID"]


def check(name, condition):
    print(("PASS " if condition else "FAIL ") + name)
    if not condition:
        raise SystemExit("check failed: " + name)


def main():
    app = Client(project_id=PID, base_url=BASE)
    app.init()
    check("init", bool(app.server_key))
    licensed = app.license(key=KEY, hwid=HWID)
    check("license", licensed["remaining"] > 80000)
    check("heartbeat", app.heartbeat() > 80000)
    check("info", app.info()["status"] == "active")
    check("variable", app.variable("offset") == "0x10")
    check("variables", app.variable()["offset"] == "0x10")
    try:
        check("file", app.file("app.bin") == b"sdk-file-secret-bytes")
    except AuthError as exc:
        if "cryptography" in str(exc):
            print("SKIP file (cryptography package not installed)")
        else:
            raise
    hooked = app.webhook("orders", data="ping")
    check("webhook", hooked["status"] == 200)
    check("table add", app.table("config", "add_row", data={"offset": "0x20", "label": "python"})["ok"])
    rows = app.table("config", "get_rows")["rows"]
    check("table rows", any(r["data"].get("label") == "python" for r in rows))

    user = Client(project_id=PID, base_url=BASE)
    check("user register", user.user_register("pyuser", "DemoPass123!", KEY) == "pyuser")
    check("user login", user.user_login("pyuser", "DemoPass123!", hwid=HWID)["remaining"] > 80000)
    sub = user.user_upgrade("pyuser", KEY2)
    check("user upgrade", sub["active"] is True and sub["remaining"] > 80000)
    check("user heartbeat", user.heartbeat() > 80000)
    check("user variable", user.variable("offset") == "0x10")

    bad = Client(project_id=PID, base_url=BASE)
    try:
        bad.license(key="ZZZZ-9999-ZZZZ-9999", hwid=HWID)
        check("bad key rejected", False)
    except AuthError as exc:
        check("bad key rejected", "Invalid key" in str(exc))
    print("PYTHON CHECKS PASSED")


if __name__ == "__main__":
    main()
