#pragma once

#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#define AUTHV4_POPEN _popen
#define AUTHV4_PCLOSE _pclose
#else
#define AUTHV4_POPEN popen
#define AUTHV4_PCLOSE pclose
#endif

namespace authv4 {

struct AuthError : std::runtime_error {
  explicit AuthError(const std::string& message) : std::runtime_error(message) {}
};

inline std::string hex_encode(const unsigned char* data, size_t len) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out += digits[data[i] >> 4];
    out += digits[data[i] & 15];
  }
  return out;
}

inline std::vector<unsigned char> hex_decode(const std::string& text) {
  std::vector<unsigned char> out;
  if (text.size() % 2 != 0) return out;
  out.reserve(text.size() / 2);
  for (size_t i = 0; i < text.size(); i += 2) {
    unsigned value = 0;
    if (sscanf(text.c_str() + i, "%2x", &value) != 1) return {};
    out.push_back((unsigned char)value);
  }
  return out;
}

inline int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

inline std::vector<unsigned char> base64_decode(const std::string& text) {
  std::vector<unsigned char> out;
  int value = 0, bits = 0;
  for (char c : text) {
    if (c == '=') break;
    int d = b64_value(c);
    if (d < 0) continue;
    value = (value << 6) | d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back((unsigned char)(value >> bits));
      value &= (1 << bits) - 1;
    }
  }
  return out;
}

inline std::string hmac_hex(const std::string& key, const std::string& message) {
  unsigned char out[32];
  unsigned int len = 0;
  HMAC(EVP_sha256(), key.data(), (int)key.size(),
       (const unsigned char*)message.data(), message.size(), out, &len);
  return hex_encode(out, len);
}

inline std::string json_escape(const std::string& text) {
  std::string out;
  for (char c : text) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c; break;
    }
  }
  return out;
}

class JsonBuilder {
  std::string out_ = "{";
  bool first_ = true;
  void comma() {
    if (!first_) out_ += ",";
    first_ = false;
  }
 public:
  void add_str(const std::string& key, const std::string& value) {
    comma();
    out_ += "\"" + json_escape(key) + "\":\"" + json_escape(value) + "\"";
  }
  void add_num(const std::string& key, long long value) {
    comma();
    out_ += "\"" + json_escape(key) + "\":" + std::to_string(value);
  }
  void add_raw(const std::string& key, const std::string& raw) {
    comma();
    out_ += "\"" + json_escape(key) + "\":" + raw;
  }
  std::string str() { return out_ + "}"; }
};

struct Json {
  enum class Type { Null, Bool, Num, Str, Obj, Arr } type = Type::Null;
  bool boolean = false;
  double number = 0;
  std::string str;
  std::map<std::string, Json> obj;
  std::vector<Json> arr;

  const Json* find(const std::string& key) const {
    if (type != Type::Obj) return nullptr;
    auto it = obj.find(key);
    return it == obj.end() ? nullptr : &it->second;
  }
  std::string get_str(const std::string& key) const {
    const Json* v = find(key);
    return (v && v->type == Type::Str) ? v->str : "";
  }
  long long get_num(const std::string& key) const {
    const Json* v = find(key);
    return (v && v->type == Type::Num) ? (long long)v->number : 0;
  }
  bool get_bool(const std::string& key) const {
    const Json* v = find(key);
    return v && v->type == Type::Bool && v->boolean;
  }
  bool has(const std::string& key) const { return find(key) != nullptr; }

  struct Parser {
    const std::string& s;
    size_t i = 0;
    void ws() {
      while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
    }
    Json value() {
      ws();
      char c = s[i];
      if (c == '{') return object();
      if (c == '[') return list();
      if (c == '"') return string();
      if (c == 't' || c == 'f') return boolean();
      if (c == 'n') {
        i += 4;
        return Json();
      }
      return number();
    }
    Json object() {
      Json v;
      v.type = Type::Obj;
      i++;
      ws();
      if (s[i] == '}') {
        i++;
        return v;
      }
      while (true) {
        ws();
        std::string key = string().str;
        ws();
        i++;
        v.obj[key] = value();
        ws();
        if (s[i++] == '}') break;
      }
      return v;
    }
    Json list() {
      Json v;
      v.type = Type::Arr;
      i++;
      ws();
      if (s[i] == ']') {
        i++;
        return v;
      }
      while (true) {
        v.arr.push_back(value());
        ws();
        if (s[i++] == ']') break;
      }
      return v;
    }
    Json string() {
      Json v;
      v.type = Type::Str;
      i++;
      while (true) {
        char c = s[i++];
        if (c == '"') break;
        if (c == '\\') {
          char e = s[i++];
          if (e == 'n') v.str += '\n';
          else if (e == 'r') v.str += '\r';
          else if (e == 't') v.str += '\t';
          else v.str += e;
        } else {
          v.str += c;
        }
      }
      return v;
    }
    Json boolean() {
      Json v;
      v.type = Type::Bool;
      if (s.compare(i, 4, "true") == 0) {
        v.boolean = true;
        i += 4;
      } else {
        i += 5;
      }
      return v;
    }
    Json number() {
      Json v;
      v.type = Type::Num;
      size_t start = i;
      while (i < s.size() && strchr("-+0123456789.eE", s[i])) i++;
      v.number = strtod(s.substr(start, i - start).c_str(), nullptr);
      return v;
    }
  };

  static Json parse(const std::string& text) {
    Parser p{text, 0};
    return p.value();
  }
};

inline std::string machine_hwid() {
  auto run = [](const char* cmd) {
    std::string out;
    FILE* pipe = AUTHV4_POPEN(cmd, "r");
    if (!pipe) return out;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) out += buf;
    AUTHV4_PCLOSE(pipe);
    return out;
  };
#ifdef _WIN32
  {
    std::string text = run("wmic csproduct get UUID");
    size_t pos = 0;
    while (pos < text.size()) {
      size_t end = text.find('\n', pos);
      std::string line = text.substr(pos, end == std::string::npos ? end : end - pos);
      std::string cleaned;
      for (char c : line) {
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') || c == '-') cleaned += c;
      }
      if (!cleaned.empty() && cleaned != "UUID") return cleaned;
      if (end == std::string::npos) break;
      pos = end + 1;
    }
  }
#elif __APPLE__
  {
    std::string text = run("ioreg -rd1 -c IOPlatformExpertDevice");
    size_t at = text.find("IOPlatformUUID");
    if (at != std::string::npos) {
      size_t eq = text.find('=', at);
      if (eq != std::string::npos) {
        size_t b = text.find('"', eq);
        if (b != std::string::npos) {
          size_t c = text.find('"', b + 1);
          if (c != std::string::npos) return text.substr(b + 1, c - b - 1);
        }
      }
    }
  }
#else
  {
    FILE* f = fopen("/etc/machine-id", "r");
    if (f) {
      char buf[128] = {0};
      if (fgets(buf, sizeof(buf), f)) {
        std::string id = buf;
        id.erase(id.find_last_not_of(" \t\r\n") + 1);
        if (!id.empty()) {
          fclose(f);
          return id;
        }
      }
      fclose(f);
    }
  }
#endif
  unsigned char digest[32];
  SHA256((const unsigned char*)"authv4-fallback", 15, digest);
  return hex_encode(digest, 16);
}

inline std::string sha256_file(const std::string& path) {
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) throw AuthError("open file: " + path);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  unsigned char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) SHA256_Update(&ctx, buf, n);
  fclose(f);
  unsigned char digest[32];
  SHA256_Final(digest, &ctx);
  return hex_encode(digest, 32);
}

inline bool verify_signature(const std::string& public_hex, const std::string& data,
                             const std::string& signature_hex) {
  std::vector<unsigned char> key = hex_decode(public_hex);
  std::vector<unsigned char> sig = hex_decode(signature_hex);
  if (key.size() != 64 || sig.size() != 64) return false;
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* x = BN_bin2bn(key.data(), 32, nullptr);
  BIGNUM* y = BN_bin2bn(key.data() + 32, 32, nullptr);
  BIGNUM* r = BN_bin2bn(sig.data(), 32, nullptr);
  BIGNUM* s = BN_bin2bn(sig.data() + 32, 32, nullptr);
  BIGNUM* order = BN_new();
  EC_GROUP_get_order(group, order, ctx);
  bool valid = false;
  EC_POINT* point = EC_POINT_new(group);
  if (EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 1 && !BN_is_zero(r) &&
      !BN_is_zero(s) && BN_cmp(r, order) < 0 && BN_cmp(s, order) < 0) {
    unsigned char digest[32];
    SHA256((const unsigned char*)data.data(), data.size(), digest);
    BIGNUM* e = BN_bin2bn(digest, 32, nullptr);
    BIGNUM* w = BN_mod_inverse(nullptr, s, order, ctx);
    BIGNUM* u1 = BN_new();
    BIGNUM* u2 = BN_new();
    BN_mod_mul(u1, e, w, order, ctx);
    BN_mod_mul(u2, r, w, order, ctx);
    EC_POINT* at = EC_POINT_new(group);
    EC_POINT* q = EC_POINT_new(group);
    EC_POINT_copy(q, point);
    EC_POINT_mul(group, at, u1, q, u2, ctx);
    BIGNUM* px = BN_new();
    EC_POINT_get_affine_coordinates(group, at, px, nullptr, ctx);
    BIGNUM* v = BN_new();
    BN_mod(v, px, order, ctx);
    valid = BN_cmp(v, r) == 0;
    BN_free(e);
    BN_free(w);
    BN_free(u1);
    BN_free(u2);
    BN_free(px);
    BN_free(v);
    EC_POINT_free(at);
    EC_POINT_free(q);
  }
  EC_POINT_free(point);
  BN_free(x);
  BN_free(y);
  BN_free(r);
  BN_free(s);
  BN_free(order);
  BN_CTX_free(ctx);
  EC_GROUP_free(group);
  return valid;
}

struct License {
  long long expires = 0;
  long long remaining = -1;
};

struct Subscription {
  long long expires = 0;
  long long remaining = -1;
  bool active = false;
};

class Client {
  static size_t write_body(char* data, size_t size, size_t count, void* out) {
    ((std::string*)out)->append(data, size * count);
    return size * count;
  }
  static bool rotation_ok(const Json& fetched, const std::string& current, const std::string& pinned) {
    const Json* rotation = fetched.find("rotation");
    if (!rotation || rotation->type != Json::Type::Obj) return false;
    const Json* nk = rotation->find("new_key");
    const Json* sig = rotation->find("signature");
    if (!nk || nk->type != Json::Type::Str || nk->str != current) return false;
    if (!sig || sig->type != Json::Type::Str) return false;
    try {
      return verify_signature(pinned, "ROTATE:" + current, sig->str);
    } catch (...) {
      return false;
    }
  }

  Json request(const std::string& method, const std::string& path, const std::string& body,
               long timeout) {
    CURL* curl = curl_easy_init();
    if (!curl) throw AuthError("curl init failed");
    std::string out;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, (base_url_ + path).c_str());
    if (method == "POST") {
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    CURLcode code = curl_easy_perform(curl);
    long http_status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (code != CURLE_OK) throw AuthError(std::string("Request failed: ") + curl_easy_strerror(code));
    if (http_status != 200) throw AuthError("Request failed: HTTP " + std::to_string(http_status));
    return Json::parse(out);
  }

  void require_ok(const Json& result, const std::string& fallback) {
    if (!result.get_bool("ok")) {
      std::string message = result.get_str("error");
      throw AuthError(message.empty() ? fallback : message);
    }
  }

 public:
  std::string project_id_;
  std::string base_url_;
  std::string app_hash_;
  std::string server_key_;
  std::string session_;
  std::string key_;
  std::string hwid_;
  std::string username_;
  long long expires_ = 0;
  long long remaining_ = -1;

  Client(const std::string& project_id, const std::string& base_url,
         const std::string& app_hash = "", const std::string& server_key = "")
      : project_id_(project_id), app_hash_(app_hash), server_key_(server_key) {
    base_url_ = base_url;
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
  }

  void init() {
    Json fetched = request("GET", "/v4/server-key", "", 15);
    std::string key = fetched.get_str("server_key");
    if (key.empty()) throw AuthError("Server key missing");
    if (!server_key_.empty() && server_key_ != key && !rotation_ok(fetched, key, server_key_)) throw AuthError("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)");
    server_key_ = key;
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    Json result = request("POST", "/v4/init", payload.str(), 15);
    require_ok(result, "Init failed");
    challenge_id_ = result.get_str("challenge_id");
    challenge_ = result.get_str("challenge");
  }

  License license(const std::string& key, const std::string& hwid = "") {
    if (challenge_.empty()) init();
    std::string use_hwid = hwid.empty() ? machine_hwid() : hwid;
    std::string challenge = challenge_;
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    payload.add_str("key", key);
    payload.add_str("hwid", use_hwid);
    payload.add_str("challenge_id", challenge_id_);
    payload.add_str("signature", hmac_hex(key, challenge));
    if (!app_hash_.empty()) payload.add_str("app_hash", app_hash_);
    challenge_.clear();
    challenge_id_.clear();
    Json result = request("POST", "/v4/license", payload.str(), 15);
    require_ok(result, "License failed");
    std::string proof_base = challenge + "|" + result.get_str("session");
    if (hmac_hex(key, proof_base) != result.get_str("server_proof")) {
      throw AuthError("Server proof mismatch");
    }
    if (!server_key_.empty() &&
        !verify_signature(server_key_, proof_base, result.get_str("signature"))) {
      throw AuthError("Server signature mismatch");
    }
    session_ = result.get_str("session");
    key_ = key;
    hwid_ = use_hwid;
    expires_ = result.get_num("expires");
    remaining_ = result.has("remaining") ? result.get_num("remaining") : -1;
    return License{expires_, remaining_};
  }

  std::string user_register(const std::string& username, const std::string& password,
                            const std::string& key, const std::string& hwid = "") {
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    payload.add_str("username", username);
    payload.add_str("password", password);
    payload.add_str("key", key);
    if (!hwid.empty()) payload.add_str("hwid", hwid);
    Json result = request("POST", "/v4/user/register", payload.str(), 15);
    require_ok(result, "Register failed");
    return result.get_str("username");
  }

  License user_login(const std::string& username, const std::string& password,
                     const std::string& hwid = "") {
    if (server_key_.empty()) init();
    std::string use_hwid = hwid.empty() ? machine_hwid() : hwid;
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    payload.add_str("username", username);
    payload.add_str("password", password);
    payload.add_str("hwid", use_hwid);
    Json result = request("POST", "/v4/user/login", payload.str(), 15);
    require_ok(result, "Login failed");
    std::string session = result.get_str("session");
    if (!server_key_.empty() &&
        !verify_signature(server_key_, "user|" + session, result.get_str("signature"))) {
      throw AuthError("Server signature mismatch");
    }
    session_ = session;
    key_ = password;
    hwid_ = use_hwid;
    username_ = username;
    const Json* sub = result.find("subscription");
    if (sub) {
      expires_ = sub->get_num("expires");
      remaining_ = sub->get_num("remaining");
    }
    return License{expires_, remaining_};
  }

  Subscription user_redeem(const std::string& username, const std::string& password,
                           const std::string& key) {
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    payload.add_str("username", username);
    payload.add_str("password", password);
    payload.add_str("key", key);
    Json result = request("POST", "/v4/user/redeem", payload.str(), 15);
    require_ok(result, "Redeem failed");
    Subscription out{0, -1, false};
    const Json* sub = result.find("subscription");
    if (sub) {
      out.expires = sub->get_num("expires");
      out.remaining = sub->get_num("remaining");
      const Json* active = sub->find("active");
      out.active = active && active->type == Json::Type::Bool && active->boolean;
    }
    return out;
  }

  Subscription user_upgrade(const std::string& username, const std::string& key) {
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    payload.add_str("username", username);
    payload.add_str("key", key);
    Json result = request("POST", "/v4/user/upgrade", payload.str(), 15);
    require_ok(result, "Upgrade failed");
    Subscription out{0, -1, false};
    const Json* sub = result.find("subscription");
    if (sub) {
      out.expires = sub->get_num("expires");
      out.remaining = sub->get_num("remaining");
      const Json* active = sub->find("active");
      out.active = active && active->type == Json::Type::Bool && active->boolean;
    }
    return out;
  }

  long long heartbeat() {
    if (session_.empty() || key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("session", session_);
    payload.add_str("key", key_);
    Json result = request("POST", "/v4/heartbeat", payload.str(), 15);
    require_ok(result, "Heartbeat failed");
    long long left = result.get_num("remaining");
    std::string base = "VERIFY:" + project_id_ + ":" + std::to_string(left);
    if (hmac_hex(key_, base) != result.get_str("proof")) {
      throw AuthError("Heartbeat proof mismatch");
    }
    if (!server_key_.empty() && !verify_signature(server_key_, base, result.get_str("signature"))) {
      throw AuthError("Heartbeat signature mismatch");
    }
    remaining_ = left;
    return left;
  }

  Json info() {
    if (key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("project_id", project_id_);
    payload.add_str("key", key_);
    payload.add_str("hwid", hwid_.empty() ? machine_hwid() : hwid_);
    Json result = request("POST", "/v4/info", payload.str(), 15);
    require_ok(result, "Info failed");
    return result;
  }

  std::map<std::string, std::string> variables() {
    if (session_.empty() || key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("session", session_);
    payload.add_str("key", key_);
    Json result = request("POST", "/v4/variable", payload.str(), 15);
    require_ok(result, "Variable failed");
    std::map<std::string, std::string> out;
    const Json* vars = result.find("variables");
    if (vars && vars->type == Json::Type::Obj) {
      for (const auto& [name, item] : vars->obj) {
        if (item.type == Json::Type::Str) out[name] = item.str;
      }
    }
    return out;
  }

  std::string variable(const std::string& name) {
    if (session_.empty() || key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("session", session_);
    payload.add_str("key", key_);
    payload.add_str("name", name);
    Json result = request("POST", "/v4/variable", payload.str(), 15);
    require_ok(result, "Variable failed");
    return result.get_str("value");
  }

  std::vector<unsigned char> file(const std::string& name) {
    if (session_.empty() || key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("session", session_);
    payload.add_str("key", key_);
    payload.add_str("name", name);
    Json result = request("POST", "/v4/file", payload.str(), 60);
    require_ok(result, "File failed");
    std::string nonce_hex = result.get_str("nonce");
    std::vector<unsigned char> file_key = hex_decode(hmac_hex(key_, "FILE_KEY:" + nonce_hex));
    std::vector<unsigned char> nonce = hex_decode(nonce_hex);
    std::vector<unsigned char> content = base64_decode(result.get_str("data"));
    std::vector<unsigned char> tag = hex_decode(result.get_str("tag"));
    if (file_key.size() != 32 || nonce.size() != 12 || tag.size() != 16) {
      throw AuthError("File decrypt failed");
    }
    std::vector<unsigned char> plain(content.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    bool ok = false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, file_key.data(), nonce.data()) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &len, (const unsigned char*)project_id_.data(),
                          (int)project_id_.size()) == 1 &&
        EVP_DecryptUpdate(ctx, plain.data(), &len, content.data(), (int)content.size()) == 1) {
      int final_len = 0;
      if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) == 1 &&
          EVP_DecryptFinal_ex(ctx, plain.data() + len, &final_len) == 1) {
        ok = true;
      }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw AuthError("File decrypt failed");
    unsigned char digest[32];
    SHA256(plain.data(), plain.size(), digest);
    if (hex_encode(digest, 32) != result.get_str("hash")) throw AuthError("File hash mismatch");
    return plain;
  }

  Json webhook(const std::string& name, const std::string& data = "") {
    if (session_.empty() || key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("session", session_);
    payload.add_str("key", key_);
    payload.add_str("name", name);
    payload.add_str("data", data);
    Json result = request("POST", "/v4/webhook", payload.str(), 30);
    require_ok(result, "Webhook failed");
    return result;
  }

  Json table(const std::string& table, const std::string& op, long long id,
             const std::string& data_json, long long limit = 100) {
    if (session_.empty() || key_.empty()) throw AuthError("Not licensed");
    JsonBuilder payload;
    payload.add_str("session", session_);
    payload.add_str("key", key_);
    payload.add_str("table", table);
    payload.add_str("op", op);
    payload.add_num("limit", limit);
    if (id != 0) payload.add_num("id", id);
    if (!data_json.empty()) payload.add_raw("data", data_json);
    Json result = request("POST", "/v4/table", payload.str(), 15);
    require_ok(result, "Table failed");
    return result;
  }

 private:
  std::string challenge_id_;
  std::string challenge_;
};

}
