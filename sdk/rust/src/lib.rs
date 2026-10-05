use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct AuthError(pub String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AuthError {}

fn fail(message: impl Into<String>) -> AuthError {
    AuthError(message.into())
}

pub fn machine_hwid() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("wmic").args(["csproduct", "get", "UUID"]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let cleaned: String = line
                    .trim()
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit() || *c == '-')
                    .collect();
                if !cleaned.is_empty() && !cleaned.eq_ignore_ascii_case("UUID") {
                    return cleaned;
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let id = id.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
        if let Ok(out) = Command::new("cat").arg("/proc/cpuinfo").output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if line.contains("Serial") {
                    if let Some(part) = line.split(':').next_back() {
                        return part.trim().to_string();
                    }
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if line.contains("IOPlatformUUID") {
                    let parts: Vec<&str> = line.split('"').collect();
                    if parts.len() >= 2 {
                        return parts[parts.len() - 2].to_string();
                    }
                }
            }
        }
    }
    let raw = format!("{}-{}-{}", std::env::consts::OS, std::env::consts::ARCH, "authv4");
    hex::encode(Sha256::digest(raw.as_bytes()))[..32].to_string()
}

pub fn sha256_file(path: &str) -> Result<String, AuthError> {
    let bytes = std::fs::read(path).map_err(|e| fail(format!("read file: {e}")))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

pub fn verify_signature(public_hex: &str, data: &str, signature_hex: &str) -> bool {
    let key = match hex::decode(public_hex) {
        Ok(k) if k.len() == 64 => k,
        _ => return false,
    };
    let sig = match hex::decode(signature_hex) {
        Ok(s) if s.len() == 64 => s,
        _ => return false,
    };
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&key);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(&sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify(data.as_bytes(), &sig).is_ok()
}

fn hmac_hex(key: &str, message: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_bytes()).expect("hmac key");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn str_field(body: &serde_json::Value, key: &str) -> String {
    body.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn rotation_ok(payload: &serde_json::Value, current: &str, pinned: &str) -> bool {
    let rotation = match payload.get("rotation") {
        Some(v) => v,
        None => return false,
    };
    if rotation.get("new_key").and_then(|v| v.as_str()) != Some(current) {
        return false;
    }
    let sig = match rotation.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    verify_signature(pinned, &format!("ROTATE:{current}"), sig)
}

fn num_field(body: &serde_json::Value, key: &str) -> i64 {
    body.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct License {
    pub expires: i64,
    pub remaining: i64,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub expires: i64,
    pub remaining: i64,
    pub active: bool,
}

pub struct Client {
    pub project_id: String,
    pub base_url: String,
    pub app_hash: Option<String>,
    pub server_key: Option<String>,
    pub session: Option<String>,
    pub key: Option<String>,
    pub hwid: Option<String>,
    pub username: Option<String>,
    pub expires: i64,
    pub remaining: i64,
    challenge_id: Option<String>,
    challenge: Option<String>,
    http: reqwest::blocking::Client,
}

impl Client {
    pub fn new(project_id: &str, base_url: &str, app_hash: Option<String>, server_key: Option<String>) -> Self {
        Client {
            project_id: project_id.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            app_hash,
            server_key,
            session: None,
            key: None,
            hwid: None,
            username: None,
            expires: 0,
            remaining: -1,
            challenge_id: None,
            challenge: None,
            http: reqwest::blocking::Client::new(),
        }
    }

    fn post(&self, path: &str, payload: &serde_json::Value, timeout: Duration) -> Result<serde_json::Value, AuthError> {
        let res = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .timeout(timeout)
            .json(payload)
            .send()
            .map_err(|e| fail(format!("request failed: {e}")))?;
        if !res.status().is_success() {
            return Err(fail(format!("request failed: HTTP {}", res.status())));
        }
        res.json::<serde_json::Value>()
            .map_err(|e| fail(format!("decode response: {e}")))
    }

    fn get(&self, path: &str, timeout: Duration) -> Result<serde_json::Value, AuthError> {
        let res = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .timeout(timeout)
            .send()
            .map_err(|e| fail(format!("request failed: {e}")))?;
        if !res.status().is_success() {
            return Err(fail(format!("request failed: HTTP {}", res.status())));
        }
        res.json::<serde_json::Value>()
            .map_err(|e| fail(format!("decode response: {e}")))
    }

    fn require_ok(body: &serde_json::Value, fallback: &str) -> Result<(), AuthError> {
        if body.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            Ok(())
        } else {
            Err(fail(str_field(body, "error").if_empty(fallback)))
        }
    }

    pub fn init(&mut self) -> Result<(), AuthError> {
        let key_resp = self.get("/v4/server-key", Duration::from_secs(15))?;
        let fetched = str_field(&key_resp, "server_key");
        if fetched.is_empty() {
            return Err(fail("Server key missing"));
        }
        if let Some(pinned) = &self.server_key {
            if pinned != &fetched && !rotation_ok(&key_resp, &fetched, pinned) {
                return Err(fail("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)"));
            }
        }
        self.server_key = Some(fetched);
        let payload = serde_json::json!({"project_id": self.project_id});
        let result = self.post("/v4/init", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Init failed")?;
        self.challenge_id = Some(str_field(&result, "challenge_id"));
        self.challenge = Some(str_field(&result, "challenge"));
        Ok(())
    }

    pub fn license(&mut self, key: &str, hwid: Option<&str>) -> Result<License, AuthError> {
        if self.challenge.is_none() {
            self.init()?;
        }
        let use_hwid = hwid.unwrap_or("").to_string();
        let use_hwid = if use_hwid.is_empty() { machine_hwid() } else { use_hwid };
        let challenge = self.challenge.clone().unwrap_or_default();
        let mut payload = serde_json::json!({
            "project_id": self.project_id,
            "key": key,
            "hwid": use_hwid,
            "challenge_id": self.challenge_id.clone().unwrap_or_default(),
            "signature": hmac_hex(key, &challenge),
        });
        if let Some(hash) = &self.app_hash {
            payload["app_hash"] = serde_json::Value::String(hash.clone());
        }
        self.challenge = None;
        self.challenge_id = None;
        let result = self.post("/v4/license", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "License failed")?;
        let proof_base = format!("{}|{}", challenge, str_field(&result, "session"));
        if hmac_hex(key, &proof_base) != str_field(&result, "server_proof") {
            return Err(fail("Server proof mismatch"));
        }
        if let Some(pinned) = &self.server_key {
            if !verify_signature(pinned, &proof_base, &str_field(&result, "signature")) {
                return Err(fail("Server signature mismatch"));
            }
        }
        self.session = Some(str_field(&result, "session"));
        self.key = Some(key.to_string());
        self.hwid = Some(use_hwid);
        self.expires = num_field(&result, "expires");
        self.remaining = result.get("remaining").and_then(|v| v.as_i64()).unwrap_or(-1);
        Ok(License { expires: self.expires, remaining: self.remaining })
    }

    pub fn user_register(&self, username: &str, password: &str, key: &str, hwid: Option<&str>) -> Result<String, AuthError> {
        let mut payload = serde_json::json!({
            "project_id": self.project_id,
            "username": username,
            "password": password,
            "key": key,
        });
        if let Some(h) = hwid {
            if !h.is_empty() {
                payload["hwid"] = serde_json::Value::String(h.to_string());
            }
        }
        let result = self.post("/v4/user/register", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Register failed")?;
        Ok(str_field(&result, "username"))
    }

    pub fn user_login(&mut self, username: &str, password: &str, hwid: Option<&str>) -> Result<License, AuthError> {
        if self.server_key.is_none() {
            self.init()?;
        }
        let use_hwid = hwid.unwrap_or("").to_string();
        let use_hwid = if use_hwid.is_empty() { machine_hwid() } else { use_hwid };
        let payload = serde_json::json!({
            "project_id": self.project_id,
            "username": username,
            "password": password,
            "hwid": use_hwid,
        });
        let result = self.post("/v4/user/login", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Login failed")?;
        let session = str_field(&result, "session");
        if let Some(pinned) = &self.server_key {
            let proof = format!("user|{session}");
            if !verify_signature(pinned, &proof, &str_field(&result, "signature")) {
                return Err(fail("Server signature mismatch"));
            }
        }
        self.session = Some(session);
        self.key = Some(password.to_string());
        self.hwid = Some(use_hwid);
        self.username = Some(username.to_string());
        if let Some(sub) = result.get("subscription") {
            self.expires = num_field(sub, "expires");
            self.remaining = num_field(sub, "remaining");
        }
        Ok(License { expires: self.expires, remaining: self.remaining })
    }

    pub fn user_redeem(&self, username: &str, password: &str, key: &str) -> Result<Subscription, AuthError> {
        let payload = serde_json::json!({
            "project_id": self.project_id,
            "username": username,
            "password": password,
            "key": key,
        });
        let result = self.post("/v4/user/redeem", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Redeem failed")?;
        let sub = result.get("subscription").cloned().unwrap_or(serde_json::Value::Null);
        Ok(Subscription {
            expires: num_field(&sub, "expires"),
            remaining: num_field(&sub, "remaining"),
            active: sub.get("active").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }

    pub fn user_upgrade(&self, username: &str, key: &str) -> Result<Subscription, AuthError> {
        let payload = serde_json::json!({
            "project_id": self.project_id,
            "username": username,
            "key": key,
        });
        let result = self.post("/v4/user/upgrade", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Upgrade failed")?;
        let sub = result.get("subscription").cloned().unwrap_or(serde_json::Value::Null);
        Ok(Subscription {
            expires: num_field(&sub, "expires"),
            remaining: num_field(&sub, "remaining"),
            active: sub.get("active").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }

    pub fn heartbeat(&mut self) -> Result<i64, AuthError> {
        let (session, key) = match (&self.session, &self.key) {
            (Some(s), Some(k)) => (s.clone(), k.clone()),
            _ => return Err(fail("Not licensed")),
        };
        let payload = serde_json::json!({"session": session, "key": key});
        let result = self.post("/v4/heartbeat", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Heartbeat failed")?;
        let left = num_field(&result, "remaining");
        let base = format!("VERIFY:{}:{}", self.project_id, left);
        if hmac_hex(&key, &base) != str_field(&result, "proof") {
            return Err(fail("Heartbeat proof mismatch"));
        }
        if let Some(pinned) = &self.server_key {
            if !verify_signature(pinned, &base, &str_field(&result, "signature")) {
                return Err(fail("Heartbeat signature mismatch"));
            }
        }
        self.remaining = left;
        Ok(left)
    }

    pub fn info(&self) -> Result<serde_json::Value, AuthError> {
        let key = self.key.clone().ok_or_else(|| fail("Not licensed"))?;
        let hwid = match &self.hwid {
            Some(h) if !h.is_empty() => h.clone(),
            _ => machine_hwid(),
        };
        let payload = serde_json::json!({"project_id": self.project_id, "key": key, "hwid": hwid});
        let result = self.post("/v4/info", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Info failed")?;
        Ok(result)
    }

    pub fn variables(&self) -> Result<HashMap<String, String>, AuthError> {
        let (session, key) = match (&self.session, &self.key) {
            (Some(s), Some(k)) => (s.clone(), k.clone()),
            _ => return Err(fail("Not licensed")),
        };
        let payload = serde_json::json!({"session": session, "key": key});
        let result = self.post("/v4/variable", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Variable failed")?;
        let mut out = HashMap::new();
        if let Some(vars) = result.get("variables").and_then(|v| v.as_object()) {
            for (k, v) in vars {
                if let Some(text) = v.as_str() {
                    out.insert(k.clone(), text.to_string());
                }
            }
        }
        Ok(out)
    }

    pub fn variable(&self, name: &str) -> Result<String, AuthError> {
        let (session, key) = match (&self.session, &self.key) {
            (Some(s), Some(k)) => (s.clone(), k.clone()),
            _ => return Err(fail("Not licensed")),
        };
        let payload = serde_json::json!({"session": session, "key": key, "name": name});
        let result = self.post("/v4/variable", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Variable failed")?;
        Ok(str_field(&result, "value"))
    }

    pub fn file(&self, name: &str) -> Result<Vec<u8>, AuthError> {
        let (session, key) = match (&self.session, &self.key) {
            (Some(s), Some(k)) => (s.clone(), k.clone()),
            _ => return Err(fail("Not licensed")),
        };
        let payload = serde_json::json!({"session": session, "key": key, "name": name});
        let result = self.post("/v4/file", &payload, Duration::from_secs(60))?;
        Self::require_ok(&result, "File failed")?;
        let nonce_hex = str_field(&result, "nonce");
        let file_key = hex::decode(hmac_hex(&key, &format!("FILE_KEY:{nonce_hex}")))
            .map_err(|_| fail("decode file key"))?;
        let nonce = hex::decode(&nonce_hex).map_err(|_| fail("decode nonce"))?;
        let mut sealed = B64.decode(str_field(&result, "data")).map_err(|_| fail("decode file data"))?;
        let tag = hex::decode(str_field(&result, "tag")).map_err(|_| fail("decode file tag"))?;
        sealed.extend_from_slice(&tag);
        let cipher = Aes256Gcm::new_from_slice(&file_key).map_err(|e| fail(format!("file cipher: {e}")))?;
        let nonce_ga = (&nonce[..]).try_into().map_err(|_| fail("bad nonce length"))?;
        let plain = cipher
            .decrypt(
                nonce_ga,
                Payload { msg: &sealed, aad: self.project_id.as_bytes() },
            )
            .map_err(|_| fail("File decrypt failed"))?;
        if hex::encode(Sha256::digest(&plain)) != str_field(&result, "hash") {
            return Err(fail("File hash mismatch"));
        }
        Ok(plain)
    }

    pub fn webhook(&self, name: &str, data: &str) -> Result<serde_json::Value, AuthError> {
        let (session, key) = match (&self.session, &self.key) {
            (Some(s), Some(k)) => (s.clone(), k.clone()),
            _ => return Err(fail("Not licensed")),
        };
        let payload = serde_json::json!({"session": session, "key": key, "name": name, "data": data});
        let result = self.post("/v4/webhook", &payload, Duration::from_secs(30))?;
        Self::require_ok(&result, "Webhook failed")?;
        Ok(result)
    }

    pub fn table(
        &self,
        table: &str,
        op: &str,
        id: Option<i64>,
        data: Option<serde_json::Value>,
        limit: i64,
    ) -> Result<serde_json::Value, AuthError> {
        let (session, key) = match (&self.session, &self.key) {
            (Some(s), Some(k)) => (s.clone(), k.clone()),
            _ => return Err(fail("Not licensed")),
        };
        let mut payload = serde_json::json!({
            "session": session, "key": key, "table": table, "op": op, "limit": limit,
        });
        if let Some(row_id) = id {
            payload["id"] = serde_json::Value::from(row_id);
        }
        if let Some(row_data) = data {
            payload["data"] = row_data;
        }
        let result = self.post("/v4/table", &payload, Duration::from_secs(15))?;
        Self::require_ok(&result, "Table failed")?;
        Ok(result)
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() { fallback.to_string() } else { self }
    }
}
