import base64
import hashlib
import hmac
import json
import platform
import re
import subprocess
import urllib.request

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


class AuthError(Exception):
    pass


def machine_hwid():
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                stderr=subprocess.DEVNULL
            ).decode().strip().splitlines()
            for line in result:
                line = line.strip()
                if line and line.upper() != "UUID":
                    cleaned = re.sub(r"[^a-fA-F0-9-]", "", line)
                    if cleaned:
                        return cleaned
        elif system == "Linux":
            try:
                with open("/etc/machine-id", "r") as handle:
                    value = handle.read().strip()
                    if value:
                        return value
            except OSError:
                pass
            result = subprocess.check_output(
                ["cat", "/proc/cpuinfo"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in result.splitlines():
                if "Serial" in line:
                    return line.split(":")[-1].strip()
        elif system == "Darwin":
            result = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in result.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
    except Exception:
        pass
    raw = platform.node() + platform.processor() + platform.machine()
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P256_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] - 3) * pow(2 * p[1], -1, P256_P) % P256_P
    else:
        lam = (q[1] - p[1]) * pow((q[0] - p[0]) % P256_P, -1, P256_P) % P256_P
    x = (lam * lam - p[0] - q[0]) % P256_P
    return (x, (lam * (p[0] - x) - p[1]) % P256_P)


def _scalar_mult(point, scalar):
    result = None
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def verify_signature(public_hex, data, signature_hex):
    try:
        raw_key = bytes.fromhex(public_hex)
        raw_sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(raw_key) != 64 or len(raw_sig) != 64:
        return False
    qx = int.from_bytes(raw_key[:32], "big")
    qy = int.from_bytes(raw_key[32:], "big")
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    if r <= 0 or r >= P256_N or s <= 0 or s >= P256_N:
        return False
    digest = hashlib.sha256(data.encode()).digest()
    e = int.from_bytes(digest, "big")
    w = pow(s, -1, P256_N)
    u1 = (e * w) % P256_N
    u2 = (r * w) % P256_N
    point = _point_add(_scalar_mult((P256_GX, P256_GY), u1), _scalar_mult((qx, qy), u2))
    if point is None:
        return False
    return point[0] % P256_N == r


class Client:
    def __init__(self, project_id, base_url, app_hash=None, server_key=None, key=None, hwid=None):
        self.project_id = project_id
        self.base_url = base_url.rstrip("/")
        self.app_hash = app_hash
        self.server_key = server_key
        self.session = None
        self.key = key
        self.hwid = hwid
        self.username = None
        self.expires = 0
        self.remaining = -1
        self._challenge_id = None
        self._challenge = None

    def _post(self, path, payload, timeout=15):
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            self.base_url + path, data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode())
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError("Request failed: " + str(exc))

    def _get(self, path, timeout=15):
        try:
            with urllib.request.urlopen(self.base_url + path, timeout=timeout) as response:
                return json.loads(response.read().decode())
        except Exception as exc:
            raise AuthError("Request failed: " + str(exc))

    def _signed(self, key, message):
        return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

    def _rotation_ok(self, payload, current):
        rotation = payload.get("rotation")
        if not isinstance(rotation, dict):
            return False
        if rotation.get("new_key") != current:
            return False
        sig = rotation.get("signature")
        if not isinstance(sig, str):
            return False
        return verify_signature(self.server_key, "ROTATE:" + current, sig)

    def init(self):
        payload = self._get("/v4/server-key")
        fetched = payload.get("server_key", "")
        if not fetched:
            raise AuthError("Server key missing")
        if self.server_key and not hmac.compare_digest(self.server_key, fetched):
            if not self._rotation_ok(payload, fetched):
                raise AuthError("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)")
        self.server_key = fetched
        result = self._post("/v4/init", {"project_id": self.project_id})
        if not result.get("ok"):
            raise AuthError(result.get("error", "Init failed"))
        self._challenge_id = result["challenge_id"]
        self._challenge = result["challenge"]
        return self._challenge

    def license(self, key=None, hwid=None):
        use_key = key or self.key
        if not use_key:
            raise AuthError("No license key")
        if not self._challenge:
            self.init()
        use_hwid = hwid or self.hwid or machine_hwid()
        challenge = self._challenge
        signature = self._signed(use_key, challenge)
        payload = {
            "project_id": self.project_id, "key": use_key, "hwid": use_hwid,
            "challenge_id": self._challenge_id, "signature": signature,
        }
        if self.app_hash:
            payload["app_hash"] = self.app_hash
        self._challenge = None
        self._challenge_id = None
        result = self._post("/v4/license", payload)
        if not result.get("ok"):
            raise AuthError(result.get("error", "License failed"))
        session = result["session"]
        proof_base = challenge + "|" + session
        expected_proof = self._signed(use_key, proof_base)
        if not hmac.compare_digest(expected_proof, result.get("server_proof", "")):
            raise AuthError("Server proof mismatch")
        if self.server_key and not verify_signature(self.server_key, proof_base, result.get("signature", "")):
            raise AuthError("Server signature mismatch")
        self.session = session
        self.key = use_key
        self.hwid = use_hwid
        self.expires = result.get("expires", 0)
        self.remaining = result.get("remaining", -1)
        return {"expires": self.expires, "remaining": self.remaining}

    def user_register(self, username, password, key, hwid=None):
        payload = {"project_id": self.project_id, "username": username, "password": password, "key": key}
        if hwid:
            payload["hwid"] = hwid
        result = self._post("/v4/user/register", payload)
        if not result.get("ok"):
            raise AuthError(result.get("error", "Register failed"))
        return result["username"]

    def user_login(self, username, password, hwid=None):
        if not self.server_key:
            self.init()
        use_hwid = hwid or machine_hwid()
        result = self._post("/v4/user/login", {
            "project_id": self.project_id, "username": username,
            "password": password, "hwid": use_hwid,
        })
        if not result.get("ok"):
            raise AuthError(result.get("error", "Login failed"))
        session = result["session"]
        if self.server_key and not verify_signature(self.server_key, "user|" + session, result.get("signature", "")):
            raise AuthError("Server signature mismatch")
        self.session = session
        self.key = password
        self.hwid = use_hwid
        self.username = username
        sub = result.get("subscription", {})
        self.expires = sub.get("expires", 0)
        self.remaining = sub.get("remaining", -1)
        return {"expires": self.expires, "remaining": self.remaining}

    def user_redeem(self, username, password, key):
        result = self._post("/v4/user/redeem", {
            "project_id": self.project_id, "username": username,
            "password": password, "key": key,
        })
        if not result.get("ok"):
            raise AuthError(result.get("error", "Redeem failed"))
        return result["subscription"]

    def user_upgrade(self, username, key):
        result = self._post("/v4/user/upgrade", {
            "project_id": self.project_id, "username": username, "key": key,
        })
        if not result.get("ok"):
            raise AuthError(result.get("error", "Upgrade failed"))
        return result["subscription"]

    def heartbeat(self):
        if not self.session or not self.key:
            raise AuthError("Not licensed")
        result = self._post("/v4/heartbeat", {"session": self.session, "key": self.key})
        if not result.get("ok"):
            raise AuthError(result.get("error", "Heartbeat failed"))
        remaining = result["remaining"]
        expected = self._signed(self.key, "VERIFY:" + self.project_id + ":" + str(remaining))
        if not hmac.compare_digest(expected, result.get("proof", "")):
            raise AuthError("Heartbeat proof mismatch")
        if self.server_key and not verify_signature(self.server_key, "VERIFY:" + self.project_id + ":" + str(remaining), result.get("signature", "")):
            raise AuthError("Heartbeat signature mismatch")
        self.remaining = remaining
        return remaining

    def info(self):
        if not self.key:
            raise AuthError("Not licensed")
        result = self._post("/v4/info", {
            "project_id": self.project_id, "key": self.key, "hwid": self.hwid or machine_hwid(),
        })
        if not result.get("ok"):
            raise AuthError(result.get("error", "Info failed"))
        return result

    def variable(self, name=None):
        if not self.session or not self.key:
            raise AuthError("Not licensed")
        payload = {"session": self.session, "key": self.key}
        if name:
            payload["name"] = name
        result = self._post("/v4/variable", payload)
        if not result.get("ok"):
            raise AuthError(result.get("error", "Variable failed"))
        if name:
            return result["value"]
        return result["variables"]

    def file(self, name):
        if not self.session or not self.key:
            raise AuthError("Not licensed")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise AuthError("File download needs the cryptography package: pip install cryptography")
        result = self._post("/v4/file", {"session": self.session, "key": self.key, "name": name}, timeout=60)
        if not result.get("ok"):
            raise AuthError(result.get("error", "File failed"))
        file_key = bytes.fromhex(self._signed(self.key, "FILE_KEY:" + result["nonce"]))
        nonce = bytes.fromhex(result["nonce"])
        sealed = base64.b64decode(result["data"]) + bytes.fromhex(result["tag"])
        plain = AESGCM(file_key).decrypt(nonce, sealed, self.project_id.encode())
        if hashlib.sha256(plain).hexdigest() != result["hash"]:
            raise AuthError("File hash mismatch")
        return plain

    def webhook(self, name, data=""):
        if not self.session or not self.key:
            raise AuthError("Not licensed")
        result = self._post("/v4/webhook", {"session": self.session, "key": self.key, "name": name, "data": data}, timeout=30)
        if not result.get("ok"):
            raise AuthError(result.get("error", "Webhook failed"))
        return result

    def table(self, table, op, row_id=None, data=None, limit=100):
        if not self.session or not self.key:
            raise AuthError("Not licensed")
        payload = {"session": self.session, "key": self.key, "table": table, "op": op, "limit": limit}
        if row_id is not None:
            payload["id"] = row_id
        if data is not None:
            payload["data"] = data
        result = self._post("/v4/table", payload)
        if not result.get("ok"):
            raise AuthError(result.get("error", "Table failed"))
        return result
