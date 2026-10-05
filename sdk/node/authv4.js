const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const { execSync } = require("child_process");

class AuthError extends Error {}

function machineHwid() {
  try {
    if (process.platform === "win32") {
      const out = execSync("wmic csproduct get UUID", { stdio: ["ignore", "pipe", "ignore"] }).toString();
      for (const line of out.split("\n")) {
        const cleaned = line.trim().replace(/[^a-fA-F0-9-]/g, "");
        if (cleaned && cleaned.toUpperCase() !== "UUID") return cleaned;
      }
    } else if (process.platform === "linux") {
      try {
        const id = fs.readFileSync("/etc/machine-id", "utf8").trim();
        if (id) return id;
      } catch {}
      const cpu = execSync("cat /proc/cpuinfo", { stdio: ["ignore", "pipe", "ignore"] }).toString();
      for (const line of cpu.split("\n")) {
        if (line.includes("Serial")) return line.split(":").pop().trim();
      }
    } else if (process.platform === "darwin") {
      const out = execSync("ioreg -rd1 -c IOPlatformExpertDevice", { stdio: ["ignore", "pipe", "ignore"] }).toString();
      for (const line of out.split("\n")) {
        if (line.includes("IOPlatformUUID")) return line.split('"').slice(-2, -1)[0];
      }
    }
  } catch {}
  return crypto.createHash("sha256").update(os.hostname() + os.arch() + os.platform()).digest("hex").slice(0, 32);
}

function sha256File(path) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(path, "r");
  const buf = Buffer.alloc(65536);
  let n;
  while ((n = fs.readSync(fd, buf, 0, buf.length)) > 0) hash.update(buf.subarray(0, n));
  fs.closeSync(fd);
  return hash.digest("hex");
}

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function verifySignature(publicHex, data, signatureHex) {
  try {
    const rawKey = Buffer.from(publicHex, "hex");
    const rawSig = Buffer.from(signatureHex, "hex");
    if (rawKey.length !== 64 || rawSig.length !== 64) return false;
    const key = crypto.createPublicKey({
      format: "jwk",
      key: { kty: "EC", crv: "P-256", x: b64url(rawKey.subarray(0, 32)), y: b64url(rawKey.subarray(32)) },
    });
    return crypto.verify("sha256", Buffer.from(data), { key, dsaEncoding: "ieee-p1363" }, rawSig);
  } catch {
    return false;
  }
}

class Client {
  constructor({ projectId, baseUrl, appHash = null, serverKey = null, key = null, hwid = null }) {
    this.projectId = projectId;
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.appHash = appHash;
    this.serverKey = serverKey;
    this.session = null;
    this.key = key;
    this.hwid = hwid;
    this.expires = 0;
    this.remaining = -1;
    this._challengeId = null;
    this._challenge = null;
  }

  _signed(key, message) {
    return crypto.createHmac("sha256", key).update(message).digest("hex");
  }

  async _post(path, payload, timeoutMs = 15000) {
    let res;
    try {
      res = await fetch(this.baseUrl + path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new AuthError("Request failed: " + err.message);
    }
    if (!res.ok) throw new AuthError("Request failed: HTTP " + res.status);
    return res.json();
  }

  async _get(path, timeoutMs = 15000) {
    let res;
    try {
      res = await fetch(this.baseUrl + path, { signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      throw new AuthError("Request failed: " + err.message);
    }
    if (!res.ok) throw new AuthError("Request failed: HTTP " + res.status);
    return res.json();
  }

  _rotationOk(payload, current) {
    const rotation = payload && payload.rotation;
    if (!rotation || rotation.new_key !== current || typeof rotation.signature !== "string") return false;
    try {
      return verifySignature(this.serverKey, "ROTATE:" + current, rotation.signature);
    } catch {
      return false;
    }
  }

  async init() {
    const payload = await this._get("/v4/server-key");
    const fetched = payload.server_key || "";
    if (!fetched) throw new AuthError("Server key missing");
    if (this.serverKey && this.serverKey !== fetched && !this._rotationOk(payload, fetched)) throw new AuthError("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)");
    this.serverKey = fetched;
    const result = await this._post("/v4/init", { project_id: this.projectId });
    if (!result.ok) throw new AuthError(result.error || "Init failed");
    this._challengeId = result.challenge_id;
    this._challenge = result.challenge;
    return this._challenge;
  }

  async license(key = null, hwid = null) {
    const useKey = key || this.key;
    if (!useKey) throw new AuthError("No license key");
    if (!this._challenge) await this.init();
    const useHwid = hwid || this.hwid || machineHwid();
    const challenge = this._challenge;
    const payload = {
      project_id: this.projectId,
      key: useKey,
      hwid: useHwid,
      challenge_id: this._challengeId,
      signature: this._signed(useKey, challenge),
    };
    if (this.appHash) payload.app_hash = this.appHash;
    this._challenge = null;
    this._challengeId = null;
    const result = await this._post("/v4/license", payload);
    if (!result.ok) throw new AuthError(result.error || "License failed");
    const proofBase = challenge + "|" + result.session;
    if (this._signed(useKey, proofBase) !== (result.server_proof || "")) {
      throw new AuthError("Server proof mismatch");
    }
    if (this.serverKey && !verifySignature(this.serverKey, proofBase, result.signature || "")) {
      throw new AuthError("Server signature mismatch");
    }
    this.session = result.session;
    this.key = useKey;
    this.hwid = useHwid;
    this.expires = result.expires || 0;
    this.remaining = result.remaining !== undefined ? result.remaining : -1;
    return { expires: this.expires, remaining: this.remaining };
  }

  async userRegister(username, password, key, hwid = null) {
    const payload = { project_id: this.projectId, username, password, key };
    if (hwid) payload.hwid = hwid;
    const result = await this._post("/v4/user/register", payload);
    if (!result.ok) throw new AuthError(result.error || "Register failed");
    return result.username;
  }

  async userLogin(username, password, hwid = null) {
    if (!this.serverKey) await this.init();
    const useHwid = hwid || machineHwid();
    const result = await this._post("/v4/user/login", {
      project_id: this.projectId,
      username,
      password,
      hwid: useHwid,
    });
    if (!result.ok) throw new AuthError(result.error || "Login failed");
    if (this.serverKey && !verifySignature(this.serverKey, "user|" + result.session, result.signature || "")) {
      throw new AuthError("Server signature mismatch");
    }
    this.session = result.session;
    this.key = password;
    this.hwid = useHwid;
    this.username = username;
    const sub = result.subscription || {};
    this.expires = sub.expires || 0;
    this.remaining = sub.remaining !== undefined ? sub.remaining : -1;
    return { expires: this.expires, remaining: this.remaining };
  }

  async userRedeem(username, password, key) {
    const result = await this._post("/v4/user/redeem", {
      project_id: this.projectId,
      username,
      password,
      key,
    });
    if (!result.ok) throw new AuthError(result.error || "Redeem failed");
    return result.subscription;
  }

  async userUpgrade(username, key) {
    const result = await this._post("/v4/user/upgrade", {
      project_id: this.projectId,
      username,
      key,
    });
    if (!result.ok) throw new AuthError(result.error || "Upgrade failed");
    return result.subscription;
  }

  async heartbeat() {
    if (!this.session || !this.key) throw new AuthError("Not licensed");
    const result = await this._post("/v4/heartbeat", { session: this.session, key: this.key });
    if (!result.ok) throw new AuthError(result.error || "Heartbeat failed");
    const base = "VERIFY:" + this.projectId + ":" + result.remaining;
    if (this._signed(this.key, base) !== (result.proof || "")) throw new AuthError("Heartbeat proof mismatch");
    if (this.serverKey && !verifySignature(this.serverKey, base, result.signature || "")) {
      throw new AuthError("Heartbeat signature mismatch");
    }
    this.remaining = result.remaining;
    return this.remaining;
  }

  async info() {
    if (!this.key) throw new AuthError("Not licensed");
    const result = await this._post("/v4/info", {
      project_id: this.projectId,
      key: this.key,
      hwid: this.hwid || machineHwid(),
    });
    if (!result.ok) throw new AuthError(result.error || "Info failed");
    return result;
  }

  async variable(name = null) {
    if (!this.session || !this.key) throw new AuthError("Not licensed");
    const payload = { session: this.session, key: this.key };
    if (name) payload.name = name;
    const result = await this._post("/v4/variable", payload);
    if (!result.ok) throw new AuthError(result.error || "Variable failed");
    return name ? result.value : result.variables;
  }

  async file(name) {
    if (!this.session || !this.key) throw new AuthError("Not licensed");
    const result = await this._post("/v4/file", { session: this.session, key: this.key, name }, 60000);
    if (!result.ok) throw new AuthError(result.error || "File failed");
    const fileKey = Buffer.from(this._signed(this.key, "FILE_KEY:" + result.nonce), "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", fileKey, Buffer.from(result.nonce, "hex"));
    decipher.setAuthTag(Buffer.from(result.tag, "hex"));
    decipher.setAAD(Buffer.from(this.projectId));
    let plain;
    try {
      plain = Buffer.concat([decipher.update(Buffer.from(result.data, "base64")), decipher.final()]);
    } catch {
      throw new AuthError("File decrypt failed");
    }
    if (crypto.createHash("sha256").update(plain).digest("hex") !== result.hash) {
      throw new AuthError("File hash mismatch");
    }
    return plain;
  }

  async webhook(name, data = "") {
    if (!this.session || !this.key) throw new AuthError("Not licensed");
    const result = await this._post("/v4/webhook", { session: this.session, key: this.key, name, data }, 30000);
    if (!result.ok) throw new AuthError(result.error || "Webhook failed");
    return result;
  }

  async table(table, op, { id = null, data = null, limit = 100 } = {}) {
    if (!this.session || !this.key) throw new AuthError("Not licensed");
    const payload = { session: this.session, key: this.key, table, op, limit };
    if (id !== null) payload.id = id;
    if (data !== null) payload.data = data;
    const result = await this._post("/v4/table", payload);
    if (!result.ok) throw new AuthError(result.error || "Table failed");
    return result;
  }
}

module.exports = { AuthError, Client, machineHwid, sha256File, verifySignature };
