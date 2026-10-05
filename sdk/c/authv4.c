#include "authv4.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#ifdef _WIN32
#define AUTHV4_POPEN _popen
#define AUTHV4_PCLOSE _pclose
#else
#define AUTHV4_POPEN popen
#define AUTHV4_PCLOSE pclose
#endif

static void set_error(authv4_client *c, const char *message) {
  if (c) {
    strncpy(c->error, message, sizeof(c->error) - 1);
    c->error[sizeof(c->error) - 1] = '\0';
  }
}

static void copy_field(char *dst, size_t len, const char *src) {
  if (!src) src = "";
  strncpy(dst, src, len - 1);
  dst[len - 1] = '\0';
}


static void hex_encode(const unsigned char *data, size_t len, char *out) {
  static const char *digits = "0123456789abcdef";
  size_t i;
  for (i = 0; i < len; i++) {
    out[i * 2] = digits[data[i] >> 4];
    out[i * 2 + 1] = digits[data[i] & 15];
  }
  out[len * 2] = '\0';
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_decode(const char *text, unsigned char *out, size_t outlen) {
  size_t i, len = strlen(text);
  if (len % 2 != 0 || len / 2 > outlen) return -1;
  for (i = 0; i < len; i += 2) {
    int hi = hex_val(text[i]), lo = hex_val(text[i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i / 2] = (unsigned char)((hi << 4) | lo);
  }
  return (int)(len / 2);
}

static int b64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static unsigned char *base64_decode(const char *text, size_t *outlen) {
  size_t cap = strlen(text) / 4 * 3 + 3;
  unsigned char *out = (unsigned char *)malloc(cap);
  size_t len = 0;
  int value = 0, bits = 0;
  const char *p;
  if (!out) return NULL;
  for (p = text; *p; p++) {
    int d;
    if (*p == '=') break;
    d = b64_value(*p);
    if (d < 0) continue;
    value = (value << 6) | d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[len++] = (unsigned char)(value >> bits);
      value &= (1 << bits) - 1;
    }
  }
  *outlen = len;
  return out;
}


static int json_locate(const char *from, const char *key, const char **val) {
  size_t klen = strlen(key);
  const char *p = from;
  while ((p = strchr(p, '"')) != NULL) {
    if (strncmp(p + 1, key, klen) == 0 && p[1 + klen] == '"') {
      const char *q = p + 1 + klen + 1;
      while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
      if (*q == ':') {
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        *val = q;
        return 0;
      }
    }
    p++;
  }
  return -1;
}

static int json_copy_string(const char *val, char *out, size_t outlen) {
  size_t len = 0;
  const char *p;
  if (*val != '"') return -1;
  for (p = val + 1; *p && *p != '"'; p++) {
    char c = *p;
    if (c == '\\' && p[1]) {
      p++;
      switch (*p) {
        case 'n': c = '\n'; break;
        case 'r': c = '\r'; break;
        case 't': c = '\t'; break;
        default: c = *p; break;
      }
    }
    if (len + 1 < outlen) out[len] = c;
    len++;
  }
  if (*p != '"') return -1;
  out[len < outlen ? len : outlen - 1] = '\0';
  return len < outlen ? 0 : -1;
}

int authv4_json_get(const char *json, char *out, size_t outlen, ...) {
  va_list keys;
  const char *keys_arr[8];
  int count = 0;
  const char *at, *val;
  const char *key;
  int i;
  va_start(keys, outlen);
  while (count < 8 && (key = va_arg(keys, const char *)) != NULL) keys_arr[count++] = key;
  va_end(keys);
  if (count == 0) return -1;
  at = json;
  for (i = 0; i < count; i++) {
    if (json_locate(at, keys_arr[i], &val) != 0) return -1;
    if (i + 1 < count) {
      if (*val != '{') return -1;
      at = val + 1;
    }
  }
  return json_copy_string(val, out, outlen);
}

int authv4_json_get_int(const char *json, long long *out, ...) {
  va_list keys;
  const char *keys_arr[8];
  int count = 0;
  const char *at, *val;
  const char *key;
  int i;
  char *end;
  va_start(keys, out);
  while (count < 8 && (key = va_arg(keys, const char *)) != NULL) keys_arr[count++] = key;
  va_end(keys);
  if (count == 0) return -1;
  at = json;
  for (i = 0; i < count; i++) {
    if (json_locate(at, keys_arr[i], &val) != 0) return -1;
    if (i + 1 < count) {
      if (*val != '{') return -1;
      at = val + 1;
    }
  }
  *out = strtoll(val, &end, 10);
  return end == val ? -1 : 0;
}

int authv4_json_is_true(const char *json, ...) {
  va_list keys;
  const char *keys_arr[8];
  int count = 0;
  const char *at, *val;
  const char *key;
  int i;
  va_start(keys, json);
  while (count < 8 && (key = va_arg(keys, const char *)) != NULL) keys_arr[count++] = key;
  va_end(keys);
  if (count == 0) return 0;
  at = json;
  for (i = 0; i < count; i++) {
    if (json_locate(at, keys_arr[i], &val) != 0) return 0;
    if (i + 1 < count) {
      if (*val != '{') return 0;
      at = val + 1;
    }
  }
  return strncmp(val, "true", 4) == 0;
}

int authv4_json_has_pair(const char *json, const char *key, const char *value) {
  size_t klen = strlen(key);
  const char *p = json;
  char found[512];
  while ((p = strchr(p, '"')) != NULL) {
    if (strncmp(p + 1, key, klen) == 0 && p[1 + klen] == '"') {
      const char *q = p + 1 + klen + 1;
      while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
      if (*q == ':' && json_copy_string(q + 1 + strspn(q + 1, " \t\r\n"), found, sizeof(found)) == 0) {
        if (strcmp(found, value) == 0) return 1;
      }
    }
    p++;
  }
  return 0;
}

static int json_copy_object(const char *json, const char *key, char *out, size_t outlen) {
  const char *val;
  const char *p;
  int depth;
  size_t len;
  if (json_locate(json, key, &val) != 0 || *val != '{') return -1;
  p = val;
  depth = 0;
  do {
    if (*p == '"') {
      p++;
      while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        p++;
      }
    } else if (*p == '{') {
      depth++;
    } else if (*p == '}') {
      depth--;
    }
    if (*p) p++;
  } while (*p && depth > 0);
  len = (size_t)(p - val);
  if (len + 1 > outlen) return -1;
  memcpy(out, val, len);
  out[len] = '\0';
  return 0;
}


typedef struct {
  char *data;
  size_t len;
  size_t cap;
} http_buf;

static size_t write_body(char *data, size_t size, size_t count, void *out) {
  http_buf *buf = (http_buf *)out;
  size_t need = buf->len + size * count + 1;
  if (need > buf->cap) {
    size_t grown = buf->cap ? buf->cap * 2 : 4096;
    char *next;
    while (grown < need) grown *= 2;
    next = (char *)realloc(buf->data, grown);
    if (!next) return 0;
    buf->data = next;
    buf->cap = grown;
  }
  memcpy(buf->data + buf->len, data, size * count);
  buf->len += size * count;
  buf->data[buf->len] = '\0';
  return size * count;
}

static char *http_request(authv4_client *c, const char *method, const char *path,
                           const char *body, long timeout) {
  CURL *curl = curl_easy_init();
  struct curl_slist *headers = NULL;
  http_buf buf = {NULL, 0, 0};
  char url[300];
  CURLcode code;
  long status = 0;
  if (!curl) {
    set_error(c, "curl init failed");
    return NULL;
  }
  snprintf(url, sizeof(url), "%s%s", c->base_url, path);
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl, CURLOPT_URL, url);
  if (strcmp(method, "POST") == 0) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
  code = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  if (code != CURLE_OK) {
    set_error(c, "request failed");
    free(buf.data);
    return NULL;
  }
  if (status != 200) {
    set_error(c, "request failed: bad HTTP status");
    free(buf.data);
    return NULL;
  }
  if (!buf.data) {
    buf.data = (char *)malloc(1);
    if (buf.data) buf.data[0] = '\0';
  }
  return buf.data;
}


static void hmac_hex(const char *key, const char *message, char *out65) {
  unsigned char out[32];
  unsigned int len = 0;
  HMAC(EVP_sha256(), key, (int)strlen(key), (const unsigned char *)message,
       strlen(message), out, &len);
  hex_encode(out, len, out65);
}

static void json_escape_into(const char *src, char *dst, size_t dstlen) {
  size_t j = 0;
  const char *p;
  for (p = src; *p && j + 2 < dstlen; p++) {
    switch (*p) {
      case '"': dst[j++] = '\\'; dst[j++] = '"'; break;
      case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
      case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
      case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
      case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
      default: dst[j++] = *p; break;
    }
  }
  dst[j] = '\0';
}

static int verify_signature(const char *public_hex, const char *data, const char *signature_hex) {
  unsigned char key[64], sig[64];
  EC_GROUP *group;
  BN_CTX *ctx;
  BIGNUM *x, *y, *r, *s, *order;
  EC_POINT *point, *at, *q;
  unsigned char digest[32];
  BIGNUM *e, *w, *u1, *u2, *px, *v;
  int valid = 0;
  if (hex_decode(public_hex, key, sizeof(key)) != 64) return 0;
  if (hex_decode(signature_hex, sig, sizeof(sig)) != 64) return 0;
  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  ctx = BN_CTX_new();
  x = BN_bin2bn(key, 32, NULL);
  y = BN_bin2bn(key + 32, 32, NULL);
  r = BN_bin2bn(sig, 32, NULL);
  s = BN_bin2bn(sig + 32, 32, NULL);
  order = BN_new();
  EC_GROUP_get_order(group, order, ctx);
  point = EC_POINT_new(group);
  if (EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 1 && !BN_is_zero(r) &&
      !BN_is_zero(s) && BN_cmp(r, order) < 0 && BN_cmp(s, order) < 0) {
    SHA256((const unsigned char *)data, strlen(data), digest);
    e = BN_bin2bn(digest, 32, NULL);
    w = BN_mod_inverse(NULL, s, order, ctx);
    u1 = BN_new();
    u2 = BN_new();
    BN_mod_mul(u1, e, w, order, ctx);
    BN_mod_mul(u2, r, w, order, ctx);
    at = EC_POINT_new(group);
    q = EC_POINT_new(group);
    EC_POINT_copy(q, point);
    EC_POINT_mul(group, at, u1, q, u2, ctx);
    px = BN_new();
    EC_POINT_get_affine_coordinates(group, at, px, NULL, ctx);
    v = BN_new();
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

static int rotation_ok(const char *json, const char *current, const char *pinned) {
  char newkey[129], sig[129], msg[144];
  const char *val;
  if (json_locate(json, "rotation", &val) != 0 || *val != '{') return 0;
  if (authv4_json_get(val, newkey, sizeof(newkey), "new_key", NULL) != 0) return 0;
  if (strcmp(newkey, current) != 0) return 0;
  if (authv4_json_get(val, sig, sizeof(sig), "signature", NULL) != 0) return 0;
  snprintf(msg, sizeof(msg), "ROTATE:%s", current);
  return verify_signature(pinned, msg, sig);
}


void authv4_setup(authv4_client *c, const char *project_id, const char *base_url,
                  const char *app_hash, const char *server_key) {
  size_t len;
  memset(c, 0, sizeof(*c));
  copy_field(c->project_id, sizeof(c->project_id), project_id);
  copy_field(c->base_url, sizeof(c->base_url), base_url);
  len = strlen(c->base_url);
  while (len > 0 && c->base_url[len - 1] == '/') c->base_url[--len] = '\0';
  copy_field(c->app_hash, sizeof(c->app_hash), app_hash);
  copy_field(c->server_key, sizeof(c->server_key), server_key);
  c->remaining = -1;
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

int authv4_init(authv4_client *c) {
  char *fetched, *result, *body;
  char key[129];
  int ok = AUTHV4_ERR;
  fetched = http_request(c, "GET", "/v4/server-key", NULL, 15);
  if (!fetched) return AUTHV4_ERR;
  if (authv4_json_get(fetched, key, sizeof(key), "server_key", NULL) != 0 || !key[0]) {
    set_error(c, "Server key missing");
    free(fetched);
    return AUTHV4_ERR;
  }
  if (c->server_key[0] && strcmp(c->server_key, key) != 0 &&
      !rotation_ok(fetched, key, c->server_key)) {
    set_error(c, "Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)");
    free(fetched);
    return AUTHV4_ERR;
  }
  free(fetched);
  copy_field(c->server_key, sizeof(c->server_key), key);
  body = (char *)malloc(128);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 128, "{\"project_id\":\"%s\"}", c->project_id);
  result = http_request(c, "POST", "/v4/init", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Init failed");
  } else if (authv4_json_get(result, c->challenge_id, sizeof(c->challenge_id), "challenge_id", NULL) != 0 ||
             authv4_json_get(result, c->challenge, sizeof(c->challenge), "challenge", NULL) != 0) {
    set_error(c, "Init failed");
  } else {
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_license(authv4_client *c, const char *key, const char *hwid) {
  char use_hwid[129], signature[65], challenge[65];
  char proof_base[256], proof[65], server_proof[65], sig[129];
  char *body, *result;
  char key_esc[260], hwid_esc[260];
  int ok = AUTHV4_ERR;
  if (!c->challenge[0] && authv4_init(c) != AUTHV4_OK) return AUTHV4_ERR;
  if (hwid && hwid[0]) {
    copy_field(use_hwid, sizeof(use_hwid), hwid);
  } else if (authv4_machine_hwid(use_hwid, sizeof(use_hwid)) != 0) {
    return AUTHV4_ERR;
  }
  copy_field(challenge, sizeof(challenge), c->challenge);
  hmac_hex(key, challenge, signature);
  json_escape_into(key, key_esc, sizeof(key_esc));
  json_escape_into(use_hwid, hwid_esc, sizeof(hwid_esc));
  body = (char *)malloc(2048);
  if (!body) return AUTHV4_ERR;
  if (c->app_hash[0]) {
    snprintf(body, 2048,
             "{\"project_id\":\"%s\",\"key\":\"%s\",\"hwid\":\"%s\",\"challenge_id\":\"%s\","
             "\"signature\":\"%s\",\"app_hash\":\"%s\"}",
             c->project_id, key_esc, hwid_esc, c->challenge_id, signature, c->app_hash);
  } else {
    snprintf(body, 2048,
             "{\"project_id\":\"%s\",\"key\":\"%s\",\"hwid\":\"%s\",\"challenge_id\":\"%s\",\"signature\":\"%s\"}",
             c->project_id, key_esc, hwid_esc, c->challenge_id, signature);
  }
  c->challenge[0] = '\0';
  c->challenge_id[0] = '\0';
  result = http_request(c, "POST", "/v4/license", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "License failed");
    free(result);
    return AUTHV4_ERR;
  }
  if (authv4_json_get(result, c->session, sizeof(c->session), "session", NULL) != 0) {
    set_error(c, "License failed");
    free(result);
    return AUTHV4_ERR;
  }
  snprintf(proof_base, sizeof(proof_base), "%s|%s", challenge, c->session);
  hmac_hex(key, proof_base, proof);
  if (authv4_json_get(result, server_proof, sizeof(server_proof), "server_proof", NULL) != 0 ||
      strcmp(proof, server_proof) != 0) {
    set_error(c, "Server proof mismatch");
    free(result);
    return AUTHV4_ERR;
  }
  if (c->server_key[0]) {
    if (authv4_json_get(result, sig, sizeof(sig), "signature", NULL) != 0 ||
        !verify_signature(c->server_key, proof_base, sig)) {
      set_error(c, "Server signature mismatch");
      free(result);
      return AUTHV4_ERR;
    }
  }
  copy_field(c->key, sizeof(c->key), key);
  copy_field(c->hwid, sizeof(c->hwid), use_hwid);
  authv4_json_get_int(result, &c->expires, "expires", NULL);
  if (authv4_json_get_int(result, &c->remaining, "remaining", NULL) != 0) c->remaining = -1;
  ok = AUTHV4_OK;
  free(result);
  return ok;
}

int authv4_user_register(authv4_client *c, const char *username, const char *password, const char *key, const char *hwid) {
  char *body, *result;
  char user_esc[260], pass_esc[260], key_esc[260];
  int ok = AUTHV4_ERR;
  json_escape_into(username, user_esc, sizeof(user_esc));
  json_escape_into(password, pass_esc, sizeof(pass_esc));
  json_escape_into(key, key_esc, sizeof(key_esc));
  body = (char *)malloc(2048);
  if (!body) return AUTHV4_ERR;
  if (hwid && hwid[0]) {
    char hwid_esc[260];
    json_escape_into(hwid, hwid_esc, sizeof(hwid_esc));
    snprintf(body, 2048, "{\"project_id\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"key\":\"%s\",\"hwid\":\"%s\"}",
             c->project_id, user_esc, pass_esc, key_esc, hwid_esc);
  } else {
    snprintf(body, 2048, "{\"project_id\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"key\":\"%s\"}",
             c->project_id, user_esc, pass_esc, key_esc);
  }
  result = http_request(c, "POST", "/v4/user/register", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Register failed");
  } else {
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_user_login(authv4_client *c, const char *username, const char *password, const char *hwid) {
  char use_hwid[129], proof_base[256], sig[129];
  char *body, *result;
  char user_esc[260], pass_esc[260], hwid_esc[260];
  int ok = AUTHV4_ERR;
  if (!c->server_key[0] && authv4_init(c) != AUTHV4_OK) return AUTHV4_ERR;
  if (hwid && hwid[0]) {
    copy_field(use_hwid, sizeof(use_hwid), hwid);
  } else if (authv4_machine_hwid(use_hwid, sizeof(use_hwid)) != 0) {
    return AUTHV4_ERR;
  }
  json_escape_into(username, user_esc, sizeof(user_esc));
  json_escape_into(password, pass_esc, sizeof(pass_esc));
  json_escape_into(use_hwid, hwid_esc, sizeof(hwid_esc));
  body = (char *)malloc(2048);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 2048, "{\"project_id\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"hwid\":\"%s\"}",
           c->project_id, user_esc, pass_esc, hwid_esc);
  result = http_request(c, "POST", "/v4/user/login", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Login failed");
    free(result);
    return AUTHV4_ERR;
  }
  if (authv4_json_get(result, c->session, sizeof(c->session), "session", NULL) != 0) {
    set_error(c, "Login failed");
    free(result);
    return AUTHV4_ERR;
  }
  snprintf(proof_base, sizeof(proof_base), "user|%s", c->session);
  if (c->server_key[0]) {
    if (authv4_json_get(result, sig, sizeof(sig), "signature", NULL) != 0 ||
        !verify_signature(c->server_key, proof_base, sig)) {
      set_error(c, "Server signature mismatch");
      free(result);
      return AUTHV4_ERR;
    }
  }
  copy_field(c->key, sizeof(c->key), password);
  copy_field(c->hwid, sizeof(c->hwid), use_hwid);
  copy_field(c->username, sizeof(c->username), username);
  authv4_json_get_int(result, &c->expires, "subscription", "expires", NULL);
  if (authv4_json_get_int(result, &c->remaining, "subscription", "remaining", NULL) != 0) {
    c->remaining = -1;
  }
  free(result);
  ok = AUTHV4_OK;
  return ok;
}

int authv4_user_redeem(authv4_client *c, const char *username, const char *password, const char *key) {
  char *body, *result;
  char user_esc[260], pass_esc[260], key_esc[260];
  int ok = AUTHV4_ERR;
  json_escape_into(username, user_esc, sizeof(user_esc));
  json_escape_into(password, pass_esc, sizeof(pass_esc));
  json_escape_into(key, key_esc, sizeof(key_esc));
  body = (char *)malloc(2048);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 2048, "{\"project_id\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"key\":\"%s\"}",
           c->project_id, user_esc, pass_esc, key_esc);
  result = http_request(c, "POST", "/v4/user/redeem", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Redeem failed");
  } else {
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_user_upgrade(authv4_client *c, const char *username, const char *key) {
  char *body, *result;
  char user_esc[260], key_esc[260];
  int ok = AUTHV4_ERR;
  json_escape_into(username, user_esc, sizeof(user_esc));
  json_escape_into(key, key_esc, sizeof(key_esc));
  body = (char *)malloc(2048);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 2048, "{\"project_id\":\"%s\",\"username\":\"%s\",\"key\":\"%s\"}",
           c->project_id, user_esc, key_esc);
  result = http_request(c, "POST", "/v4/user/upgrade", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Upgrade failed");
  } else {
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_heartbeat(authv4_client *c) {
  char *body, *result;
  char proof_base[256], proof[65], server_proof[65], sig[129];
  long long left;
  if (!c->session[0] || !c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  body = (char *)malloc(512);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 512, "{\"session\":\"%s\",\"key\":\"%s\"}", c->session, c->key);
  result = http_request(c, "POST", "/v4/heartbeat", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Heartbeat failed");
    free(result);
    return AUTHV4_ERR;
  }
  if (authv4_json_get_int(result, &left, "remaining", NULL) != 0) {
    set_error(c, "Heartbeat failed");
    free(result);
    return AUTHV4_ERR;
  }
  snprintf(proof_base, sizeof(proof_base), "VERIFY:%s:%lld", c->project_id, left);
  hmac_hex(c->key, proof_base, proof);
  if (authv4_json_get(result, server_proof, sizeof(server_proof), "proof", NULL) != 0 ||
      strcmp(proof, server_proof) != 0) {
    set_error(c, "Heartbeat proof mismatch");
    free(result);
    return AUTHV4_ERR;
  }
  if (c->server_key[0]) {
    if (authv4_json_get(result, sig, sizeof(sig), "signature", NULL) != 0 ||
        !verify_signature(c->server_key, proof_base, sig)) {
      set_error(c, "Heartbeat signature mismatch");
      free(result);
      return AUTHV4_ERR;
    }
  }
  c->remaining = left;
  free(result);
  return AUTHV4_OK;
}

int authv4_info(authv4_client *c, char *status_out, size_t status_len, long long *remaining_out) {
  char *body, *result;
  char hwid_esc[260];
  long long left;
  int ok = AUTHV4_ERR;
  if (!c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  json_escape_into(c->hwid[0] ? c->hwid : "", hwid_esc, sizeof(hwid_esc));
  if (!hwid_esc[0]) {
    char auto_hwid[129];
    if (authv4_machine_hwid(auto_hwid, sizeof(auto_hwid)) != 0) return AUTHV4_ERR;
    json_escape_into(auto_hwid, hwid_esc, sizeof(hwid_esc));
  }
  body = (char *)malloc(1024);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 1024, "{\"project_id\":\"%s\",\"key\":\"%s\",\"hwid\":\"%s\"}", c->project_id, c->key,
           hwid_esc);
  result = http_request(c, "POST", "/v4/info", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Info failed");
  } else if (authv4_json_get(result, status_out, status_len, "status", NULL) != 0) {
    set_error(c, "Info failed");
  } else {
    if (remaining_out) {
      if (authv4_json_get_int(result, &left, "remaining", NULL) == 0) *remaining_out = left;
    }
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_variable(authv4_client *c, const char *name, char *value_out, size_t value_len) {
  char *body, *result;
  char name_esc[260];
  int ok = AUTHV4_ERR;
  if (!c->session[0] || !c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  json_escape_into(name, name_esc, sizeof(name_esc));
  body = (char *)malloc(1024);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 1024, "{\"session\":\"%s\",\"key\":\"%s\",\"name\":\"%s\"}", c->session, c->key,
           name_esc);
  result = http_request(c, "POST", "/v4/variable", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Variable failed");
  } else if (authv4_json_get(result, value_out, value_len, "value", NULL) != 0) {
    set_error(c, "Variable failed");
  } else {
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_variables(authv4_client *c, char *json_out, size_t json_len) {
  char *body, *result;
  int ok = AUTHV4_ERR;
  if (!c->session[0] || !c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  body = (char *)malloc(512);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 512, "{\"session\":\"%s\",\"key\":\"%s\"}", c->session, c->key);
  result = http_request(c, "POST", "/v4/variable", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Variable failed");
  } else if (json_copy_object(result, "variables", json_out, json_len) != 0) {
    set_error(c, "Variable failed");
  } else {
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_file(authv4_client *c, const char *name, unsigned char **data_out, size_t *len_out) {
  char *body, *result;
  char name_esc[260];
  char nonce_hex[25], tag_hex[65], hash_hex[65];
  char *data_b64 = NULL;
  unsigned char file_key[32], nonce[12], tag[16];
  unsigned char *content = NULL, *plain = NULL;
  size_t content_len = 0;
  EVP_CIPHER_CTX *ctx;
  char key_hex[65];
  int len = 0, ok = 0;
  unsigned char digest[32];
  char digest_hex[65];
  *data_out = NULL;
  *len_out = 0;
  if (!c->session[0] || !c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  json_escape_into(name, name_esc, sizeof(name_esc));
  body = (char *)malloc(1024);
  if (!body) return AUTHV4_ERR;
  snprintf(body, 1024, "{\"session\":\"%s\",\"key\":\"%s\",\"name\":\"%s\"}", c->session, c->key,
           name_esc);
  result = http_request(c, "POST", "/v4/file", body, 60);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "File failed");
    free(result);
    return AUTHV4_ERR;
  }
  if (authv4_json_get(result, nonce_hex, sizeof(nonce_hex), "nonce", NULL) != 0 ||
      authv4_json_get(result, tag_hex, sizeof(tag_hex), "tag", NULL) != 0 ||
      authv4_json_get(result, hash_hex, sizeof(hash_hex), "hash", NULL) != 0) {
    set_error(c, "File failed");
    free(result);
    return AUTHV4_ERR;
  }
  {
    const char *val;
    size_t need;
    if (json_locate(result, "data", &val) != 0 || *val != '"') {
      set_error(c, "File failed");
      free(result);
      return AUTHV4_ERR;
    }
    val++;
    need = 0;
    while (val[need] && val[need] != '"') need++;
    data_b64 = (char *)malloc(need + 1);
    if (!data_b64) {
      free(result);
      return AUTHV4_ERR;
    }
    memcpy(data_b64, val, need);
    data_b64[need] = '\0';
  }
  {
    char msg[64];
    snprintf(msg, sizeof(msg), "FILE_KEY:%s", nonce_hex);
    hmac_hex(c->key, msg, key_hex);
  }
  if (hex_decode(key_hex, file_key, sizeof(file_key)) != 32 ||
      hex_decode(nonce_hex, nonce, sizeof(nonce)) != 12 ||
      hex_decode(tag_hex, tag, sizeof(tag)) != 16) {
    set_error(c, "File decrypt failed");
    goto done;
  }
  content = base64_decode(data_b64, &content_len);
  if (!content) {
    set_error(c, "File decrypt failed");
    goto done;
  }
  plain = (unsigned char *)malloc(content_len ? content_len : 1);
  if (!plain) {
    set_error(c, "File decrypt failed");
    goto done;
  }
  ctx = EVP_CIPHER_CTX_new();
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
      EVP_DecryptInit_ex(ctx, NULL, NULL, file_key, nonce) == 1 &&
      EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char *)c->project_id,
                        (int)strlen(c->project_id)) == 1 &&
      EVP_DecryptUpdate(ctx, plain, &len, content, (int)content_len) == 1) {
    int final_len = 0;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, plain + len, &final_len) == 1) {
      ok = 1;
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) {
    set_error(c, "File decrypt failed");
    goto done;
  }
  SHA256(plain, content_len, digest);
  hex_encode(digest, 32, digest_hex);
  if (strcmp(digest_hex, hash_hex) != 0) {
    set_error(c, "File hash mismatch");
    goto done;
  }
  *data_out = plain;
  *len_out = content_len;
  plain = NULL;
done:
  free(data_b64);
  free(content);
  free(plain);
  free(result);
  return *data_out ? AUTHV4_OK : AUTHV4_ERR;
}

int authv4_webhook(authv4_client *c, const char *name, const char *data, long *status_out) {
  char *body, *result;
  char name_esc[260];
  long long status = 0;
  size_t body_len;
  int ok = AUTHV4_ERR;
  if (!c->session[0] || !c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  json_escape_into(name, name_esc, sizeof(name_esc));
  body_len = strlen(c->session) + strlen(c->key) + strlen(name_esc) + strlen(data) * 2 + 128;
  body = (char *)malloc(body_len);
  if (!body) return AUTHV4_ERR;
  {
    char *data_esc = (char *)malloc(strlen(data) * 2 + 1);
    if (!data_esc) {
      free(body);
      return AUTHV4_ERR;
    }
    json_escape_into(data, data_esc, strlen(data) * 2 + 1);
    snprintf(body, body_len, "{\"session\":\"%s\",\"key\":\"%s\",\"name\":\"%s\",\"data\":\"%s\"}", c->session,
             c->key, name_esc, data_esc);
    free(data_esc);
  }
  result = http_request(c, "POST", "/v4/webhook", body, 30);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Webhook failed");
  } else if (authv4_json_get_int(result, &status, "status", NULL) != 0) {
    set_error(c, "Webhook failed");
  } else {
    if (status_out) *status_out = (long)status;
    ok = AUTHV4_OK;
  }
  free(result);
  return ok;
}

int authv4_table(authv4_client *c, const char *table, const char *op, long long id,
                 const char *data_json, long long limit, char **resp_out) {
  char *body, *result;
  size_t body_len;
  *resp_out = NULL;
  if (!c->session[0] || !c->key[0]) {
    set_error(c, "Not licensed");
    return AUTHV4_ERR;
  }
  body_len = 512 + (data_json ? strlen(data_json) : 0);
  body = (char *)malloc(body_len);
  if (!body) return AUTHV4_ERR;
  if (id != 0 && data_json) {
    snprintf(body, body_len,
             "{\"session\":\"%s\",\"key\":\"%s\",\"table\":\"%s\",\"op\":\"%s\",\"limit\":%lld,\"id\":%lld,"
             "\"data\":%s}",
             c->session, c->key, table, op, limit, id, data_json);
  } else if (id != 0) {
    snprintf(body, body_len,
             "{\"session\":\"%s\",\"key\":\"%s\",\"table\":\"%s\",\"op\":\"%s\",\"limit\":%lld,\"id\":%lld}",
             c->session, c->key, table, op, limit, id);
  } else if (data_json) {
    snprintf(body, body_len,
             "{\"session\":\"%s\",\"key\":\"%s\",\"table\":\"%s\",\"op\":\"%s\",\"limit\":%lld,\"data\":%s}",
             c->session, c->key, table, op, limit, data_json);
  } else {
    snprintf(body, body_len,
             "{\"session\":\"%s\",\"key\":\"%s\",\"table\":\"%s\",\"op\":\"%s\",\"limit\":%lld}", c->session,
             c->key, table, op, limit);
  }
  result = http_request(c, "POST", "/v4/table", body, 15);
  free(body);
  if (!result) return AUTHV4_ERR;
  if (!authv4_json_is_true(result, "ok", NULL)) {
    authv4_json_get(result, c->error, sizeof(c->error), "error", NULL);
    if (!c->error[0]) set_error(c, "Table failed");
    free(result);
    return AUTHV4_ERR;
  }
  *resp_out = result;
  return AUTHV4_OK;
}

int authv4_machine_hwid(char *out, size_t len) {
#ifdef _WIN32
  {
    FILE *pipe = AUTHV4_POPEN("wmic csproduct get UUID", "r");
    char line[256];
    if (pipe) {
      while (fgets(line, sizeof(line), pipe)) {
        char cleaned[128];
        size_t j = 0, i;
        for (i = 0; line[i] && j + 1 < sizeof(cleaned); i++) {
          char c = line[i];
          if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') || c == '-') {
            cleaned[j++] = c;
          }
        }
        cleaned[j] = '\0';
        if (j > 0 && strcmp(cleaned, "UUID") != 0) {
          copy_field(out, len, cleaned);
          AUTHV4_PCLOSE(pipe);
          return 0;
        }
      }
      AUTHV4_PCLOSE(pipe);
    }
  }
#elif __APPLE__
  {
    FILE *pipe = AUTHV4_POPEN("ioreg -rd1 -c IOPlatformExpertDevice", "r");
    char line[512];
    if (pipe) {
      while (fgets(line, sizeof(line), pipe)) {
        if (strstr(line, "IOPlatformUUID")) {
          char *eq = strchr(line, '=');
          char *a, *b;
          if (eq && (a = strchr(eq, '"')) != NULL && (b = strchr(a + 1, '"')) != NULL) {
            *b = '\0';
            copy_field(out, len, a + 1);
            AUTHV4_PCLOSE(pipe);
            return 0;
          }
        }
      }
      AUTHV4_PCLOSE(pipe);
    }
  }
#else
  {
    FILE *f = fopen("/etc/machine-id", "r");
    if (f) {
      char buf[128];
      if (fgets(buf, sizeof(buf), f)) {
        buf[strcspn(buf, " \t\r\n")] = '\0';
        if (buf[0]) {
          copy_field(out, len, buf);
          fclose(f);
          return 0;
        }
      }
      fclose(f);
    }
  }
#endif
  {
    unsigned char digest[32];
    char hex[65];
    SHA256((const unsigned char *)"authv4-fallback", 15, digest);
    hex_encode(digest, 32, hex);
    hex[32] = '\0';
    copy_field(out, len, hex);
    return 0;
  }
}

int authv4_sha256_file(const char *path, char *out_hex) {
  FILE *f = fopen(path, "rb");
  SHA256_CTX ctx;
  unsigned char buf[65536], digest[32];
  size_t n;
  if (!f) return -1;
  SHA256_Init(&ctx);
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) SHA256_Update(&ctx, buf, n);
  fclose(f);
  SHA256_Final(digest, &ctx);
  hex_encode(digest, 32, out_hex);
  return 0;
}
