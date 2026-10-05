import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AuthV4 {

  public static class AuthException extends Exception {
    public AuthException(String message) {
      super(message);
    }
  }

  public static class License {
    public final long expires;
    public final long remaining;

    public License(long expires, long remaining) {
      this.expires = expires;
      this.remaining = remaining;
    }
  }


  static final class JsonParser {
    final String s;
    int i;

    JsonParser(String s) {
      this.s = s;
    }

    void ws() {
      while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    Object value() {
      ws();
      char c = s.charAt(i);
      if (c == '{') return object();
      if (c == '[') return list();
      if (c == '"') return string();
      if (c == 't' || c == 'f') return bool();
      if (c == 'n') {
        i += 4;
        return null;
      }
      return number();
    }

    Map<String, Object> object() {
      Map<String, Object> m = new LinkedHashMap<>();
      i++;
      ws();
      if (s.charAt(i) == '}') {
        i++;
        return m;
      }
      while (true) {
        ws();
        String k = string();
        ws();
        i++;
        m.put(k, value());
        ws();
        if (s.charAt(i++) == '}') break;
      }
      return m;
    }

    List<Object> list() {
      List<Object> l = new ArrayList<>();
      i++;
      ws();
      if (s.charAt(i) == ']') {
        i++;
        return l;
      }
      while (true) {
        l.add(value());
        ws();
        if (s.charAt(i++) == ']') break;
      }
      return l;
    }

    String string() {
      StringBuilder b = new StringBuilder();
      i++;
      while (true) {
        char c = s.charAt(i++);
        if (c == '"') break;
        if (c == '\\') {
          char e = s.charAt(i++);
          switch (e) {
            case 'n': b.append('\n'); break;
            case 'r': b.append('\r'); break;
            case 't': b.append('\t'); break;
            case 'u':
              b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
              i += 4;
              break;
            default: b.append(e); break;
          }
        } else {
          b.append(c);
        }
      }
      return b.toString();
    }

    Boolean bool() {
      if (s.startsWith("true", i)) {
        i += 4;
        return Boolean.TRUE;
      }
      i += 5;
      return Boolean.FALSE;
    }

    Number number() {
      int start = i;
      while (i < s.length() && "-+0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
      String t = s.substring(start, i);
      if (t.contains(".") || t.contains("e") || t.contains("E")) return Double.parseDouble(t);
      return Long.parseLong(t);
    }
  }

  public static Map<String, Object> parseJson(String text) {
    return new JsonParser(text).object();
  }

  static String escapeJson(String text) {
    return text.replace("\\", "\\\\").replace("\"", "\\\"")
        .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
  }

  @SuppressWarnings("unchecked")
  public static String toJson(Object value) {
    if (value == null) return "null";
    if (value instanceof String) return "\"" + escapeJson((String) value) + "\"";
    if (value instanceof Number || value instanceof Boolean) return value.toString();
    if (value instanceof Map) {
      StringBuilder b = new StringBuilder("{");
      boolean first = true;
      for (Map.Entry<String, Object> e : ((Map<String, Object>) value).entrySet()) {
        if (!first) b.append(",");
        first = false;
        b.append(toJson(e.getKey())).append(":").append(toJson(e.getValue()));
      }
      return b.append("}").toString();
    }
    if (value instanceof List) {
      StringBuilder b = new StringBuilder("[");
      boolean first = true;
      for (Object item : (List<Object>) value) {
        if (!first) b.append(",");
        first = false;
        b.append(toJson(item));
      }
      return b.append("]").toString();
    }
    throw new IllegalArgumentException("cannot encode " + value.getClass());
  }


  static String hex(byte[] raw) {
    StringBuilder b = new StringBuilder(raw.length * 2);
    for (byte x : raw) b.append(String.format("%02x", x));
    return b.toString();
  }

  static byte[] unhex(String text) {
    byte[] out = new byte[text.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  static String hmacHex(String key, String message) throws AuthException {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return hex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new AuthException("hmac failed: " + e.getMessage());
    }
  }

  static String str(Map<String, Object> body, String key) {
    Object v = body.get(key);
    return v instanceof String ? (String) v : "";
  }

  static boolean rotationOk(Map<String, Object> body, String current, String pinned) {
    Object v = body.get("rotation");
    if (!(v instanceof Map)) return false;
    Map<?, ?> rotation = (Map<?, ?>) v;
    if (!current.equals(rotation.get("new_key"))) return false;
    Object sig = rotation.get("signature");
    if (!(sig instanceof String)) return false;
    try {
      return verifySignature(pinned, "ROTATE:" + current, (String) sig);
    } catch (Exception e) {
      return false;
    }
  }

  static long num(Map<String, Object> body, String key) {
    Object v = body.get(key);
    return v instanceof Number ? ((Number) v).longValue() : 0L;
  }

  static byte[] derFromRaw(byte[] raw) {
    byte[][] parts = new byte[2][];
    for (int k = 0; k < 2; k++) {
      byte[] half = Arrays.copyOfRange(raw, k * 32, k * 32 + 32);
      int start = 0;
      while (start < 31 && half[start] == 0) start++;
      byte[] cut = Arrays.copyOfRange(half, start, 32);
      if ((cut[0] & 0x80) != 0) {
        byte[] padded = new byte[cut.length + 1];
        System.arraycopy(cut, 0, padded, 1, cut.length);
        cut = padded;
      }
      parts[k] = cut;
    }
    int len = 2 + parts[0].length + 2 + parts[1].length;
    byte[] der = new byte[2 + len];
    der[0] = 0x30;
    der[1] = (byte) len;
    int p = 2;
    for (byte[] part : parts) {
      der[p++] = 0x02;
      der[p++] = (byte) part.length;
      System.arraycopy(part, 0, der, p, part.length);
      p += part.length;
    }
    return der;
  }

  public static boolean verifySignature(String publicHex, String data, String signatureHex) {
    try {
      byte[] key = unhex(publicHex);
      byte[] sig = unhex(signatureHex);
      if (key.length != 64 || sig.length != 64) return false;
      BigInteger x = new BigInteger(1, Arrays.copyOfRange(key, 0, 32));
      BigInteger y = new BigInteger(1, Arrays.copyOfRange(key, 32, 64));
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
      PublicKey pub = KeyFactory.getInstance("EC")
          .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecSpec));
      Signature v = Signature.getInstance("SHA256withECDSA");
      v.initVerify(pub);
      v.update(data.getBytes(StandardCharsets.UTF_8));
      return v.verify(derFromRaw(sig));
    } catch (Exception e) {
      return false;
    }
  }

  static String execOut(String... cmd) {
    try {
      Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
      String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      p.waitFor();
      return out;
    } catch (Exception e) {
      return "";
    }
  }

  public static String machineHwid() {
    String os = System.getProperty("os.name", "").toLowerCase();
    try {
      if (os.contains("win")) {
        for (String line : execOut("wmic", "csproduct", "get", "UUID").split("\n")) {
          String cleaned = line.trim().replaceAll("[^a-fA-F0-9-]", "");
          if (!cleaned.isEmpty() && !cleaned.equalsIgnoreCase("UUID")) return cleaned;
        }
      } else if (os.contains("mac")) {
        for (String line : execOut("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").split("\n")) {
          if (line.contains("IOPlatformUUID")) {
            String[] parts = line.split("\"");
            return parts[parts.length - 2];
          }
        }
      } else {
        try {
          String id = Files.readString(Paths.get("/etc/machine-id")).trim();
          if (!id.isEmpty()) return id;
        } catch (IOException ignored) {
        }
        for (String line : execOut("cat", "/proc/cpuinfo").split("\n")) {
          if (line.contains("Serial")) {
            String[] parts = line.split(":");
            return parts[parts.length - 1].trim();
          }
        }
      }
    } catch (Exception ignored) {
    }
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      String raw = System.getProperty("os.name") + System.getProperty("os.arch");
      return hex(md.digest(raw.getBytes(StandardCharsets.UTF_8))).substring(0, 32);
    } catch (Exception e) {
      return "unknown-hwid";
    }
  }

  public static String sha256File(String path) throws IOException {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(Files.readAllBytes(Paths.get(path)));
      return hex(md.digest());
    } catch (Exception e) {
      throw new IOException(e.getMessage());
    }
  }

  public static class Client {
    public final String projectId;
    public final String baseUrl;
    public String appHash;
    public String serverKey;
    public String session;
    public String key;
    public String hwid;
    public long expires;
    public long remaining = -1;

    String challengeId;
    String challenge;
    public String username;
    final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    public Client(String projectId, String baseUrl, String appHash, String serverKey) {
      this.projectId = projectId;
      this.baseUrl = baseUrl.replaceAll("/+$", "");
      this.appHash = appHash;
      this.serverKey = serverKey;
    }

    Map<String, Object> post(String path, Map<String, Object> payload, long timeoutSec) throws AuthException {
      try {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(Duration.ofSeconds(timeoutSec))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(toJson(payload)))
            .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) throw new AuthException("Request failed: HTTP " + res.statusCode());
        return parseJson(res.body());
      } catch (AuthException e) {
        throw e;
      } catch (Exception e) {
        throw new AuthException("Request failed: " + e.getMessage());
      }
    }

    Map<String, Object> get(String path, long timeoutSec) throws AuthException {
      try {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(Duration.ofSeconds(timeoutSec)).GET().build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) throw new AuthException("Request failed: HTTP " + res.statusCode());
        return parseJson(res.body());
      } catch (AuthException e) {
        throw e;
      } catch (Exception e) {
        throw new AuthException("Request failed: " + e.getMessage());
      }
    }

    public void init() throws AuthException {
      Map<String, Object> keyPayload = get("/v4/server-key", 15);
      String fetched = str(keyPayload, "server_key");
      if (fetched.isEmpty()) throw new AuthException("Server key missing");
      if (serverKey != null && !serverKey.isEmpty() && !serverKey.equals(fetched) && !rotationOk(keyPayload, fetched, serverKey)) {
        throw new AuthException("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)");
      }
      serverKey = fetched;
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      Map<String, Object> result = post("/v4/init", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      challengeId = str(result, "challenge_id");
      challenge = str(result, "challenge");
    }

    public License license(String licenseKey, String hwidOverride) throws AuthException {
      if (challenge == null) init();
      String useHwid = (hwidOverride == null || hwidOverride.isEmpty()) ? machineHwid() : hwidOverride;
      String chal = challenge;
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      payload.put("key", licenseKey);
      payload.put("hwid", useHwid);
      payload.put("challenge_id", challengeId);
      payload.put("signature", hmacHex(licenseKey, chal));
      if (appHash != null && !appHash.isEmpty()) payload.put("app_hash", appHash);
      challenge = null;
      challengeId = null;
      Map<String, Object> result = post("/v4/license", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      String proofBase = chal + "|" + str(result, "session");
      if (!hmacHex(licenseKey, proofBase).equals(str(result, "server_proof"))) {
        throw new AuthException("Server proof mismatch");
      }
      if (serverKey != null && !serverKey.isEmpty()
          && !verifySignature(serverKey, proofBase, str(result, "signature"))) {
        throw new AuthException("Server signature mismatch");
      }
      session = str(result, "session");
      key = licenseKey;
      hwid = useHwid;
      expires = num(result, "expires");
      remaining = result.containsKey("remaining") ? num(result, "remaining") : -1;
      return new License(expires, remaining);
    }

    public String userRegister(String username, String password, String licenseKey, String hwidOverride) throws AuthException {
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      payload.put("username", username);
      payload.put("password", password);
      payload.put("key", licenseKey);
      if (hwidOverride != null && !hwidOverride.isEmpty()) payload.put("hwid", hwidOverride);
      Map<String, Object> result = post("/v4/user/register", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      return str(result, "username");
    }

    @SuppressWarnings("unchecked")
    public License userLogin(String username, String password, String hwidOverride) throws AuthException {
      if (serverKey == null || serverKey.isEmpty()) init();
      String useHwid = (hwidOverride == null || hwidOverride.isEmpty()) ? machineHwid() : hwidOverride;
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      payload.put("username", username);
      payload.put("password", password);
      payload.put("hwid", useHwid);
      Map<String, Object> result = post("/v4/user/login", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      String sess = str(result, "session");
      if (serverKey != null && !serverKey.isEmpty()
          && !verifySignature(serverKey, "user|" + sess, str(result, "signature"))) {
        throw new AuthException("Server signature mismatch");
      }
      session = sess;
      key = password;
      hwid = useHwid;
      this.username = username;
      Object sub = result.get("subscription");
      if (sub instanceof Map) {
        expires = num((Map<String, Object>) sub, "expires");
        remaining = num((Map<String, Object>) sub, "remaining");
      }
      return new License(expires, remaining);
    }

    public Map<String, Object> userRedeem(String username, String password, String licenseKey) throws AuthException {
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      payload.put("username", username);
      payload.put("password", password);
      payload.put("key", licenseKey);
      Map<String, Object> result = post("/v4/user/redeem", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      Object sub = result.get("subscription");
      if (sub instanceof Map) {
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) sub;
        return out;
      }
      return new LinkedHashMap<>();
    }

    public Map<String, Object> userUpgrade(String username, String licenseKey) throws AuthException {
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      payload.put("username", username);
      payload.put("key", licenseKey);
      Map<String, Object> result = post("/v4/user/upgrade", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      Object sub = result.get("subscription");
      if (sub instanceof Map) {
        @SuppressWarnings("unchecked")
        Map<String, Object> out = (Map<String, Object>) sub;
        return out;
      }
      return new LinkedHashMap<>();
    }

    public long heartbeat() throws AuthException {
      if (session == null || key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("session", session);
      payload.put("key", key);
      Map<String, Object> result = post("/v4/heartbeat", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      long left = num(result, "remaining");
      String base = "VERIFY:" + projectId + ":" + left;
      if (!hmacHex(key, base).equals(str(result, "proof"))) throw new AuthException("Heartbeat proof mismatch");
      if (serverKey != null && !serverKey.isEmpty() && !verifySignature(serverKey, base, str(result, "signature"))) {
        throw new AuthException("Heartbeat signature mismatch");
      }
      remaining = left;
      return left;
    }

    public Map<String, Object> info() throws AuthException {
      if (key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("project_id", projectId);
      payload.put("key", key);
      payload.put("hwid", (hwid == null || hwid.isEmpty()) ? machineHwid() : hwid);
      Map<String, Object> result = post("/v4/info", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      return result;
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> variables() throws AuthException {
      if (session == null || key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("session", session);
      payload.put("key", key);
      Map<String, Object> result = post("/v4/variable", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      Map<String, String> out = new LinkedHashMap<>();
      Object vars = result.get("variables");
      if (vars instanceof Map) {
        for (Map.Entry<String, Object> e : ((Map<String, Object>) vars).entrySet()) {
          if (e.getValue() instanceof String) out.put(e.getKey(), (String) e.getValue());
        }
      }
      return out;
    }

    public String variable(String name) throws AuthException {
      if (session == null || key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("session", session);
      payload.put("key", key);
      payload.put("name", name);
      Map<String, Object> result = post("/v4/variable", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      return str(result, "value");
    }

    public byte[] file(String name) throws AuthException {
      if (session == null || key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("session", session);
      payload.put("key", key);
      payload.put("name", name);
      Map<String, Object> result = post("/v4/file", payload, 60);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      try {
        String nonceHex = str(result, "nonce");
        byte[] fileKey = unhex(hmacHex(key, "FILE_KEY:" + nonceHex));
        byte[] nonce = unhex(nonceHex);
        byte[] content = Base64.getDecoder().decode(str(result, "data"));
        byte[] tag = unhex(str(result, "tag"));
        byte[] sealed = new byte[content.length + tag.length];
        System.arraycopy(content, 0, sealed, 0, content.length);
        System.arraycopy(tag, 0, sealed, content.length, tag.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(fileKey, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(projectId.getBytes(StandardCharsets.UTF_8));
        byte[] plain = cipher.doFinal(sealed);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        if (!hex(md.digest(plain)).equals(str(result, "hash"))) throw new AuthException("File hash mismatch");
        return plain;
      } catch (AuthException e) {
        throw e;
      } catch (Exception e) {
        throw new AuthException("File decrypt failed: " + e.getMessage());
      }
    }

    public Map<String, Object> webhook(String name, String data) throws AuthException {
      if (session == null || key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("session", session);
      payload.put("key", key);
      payload.put("name", name);
      payload.put("data", data);
      Map<String, Object> result = post("/v4/webhook", payload, 30);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      return result;
    }

    public Map<String, Object> table(String table, String op, Long id, Map<String, Object> data, int limit)
        throws AuthException {
      if (session == null || key == null) throw new AuthException("Not licensed");
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("session", session);
      payload.put("key", key);
      payload.put("table", table);
      payload.put("op", op);
      payload.put("limit", (long) limit);
      if (id != null) payload.put("id", id);
      if (data != null) payload.put("data", data);
      Map<String, Object> result = post("/v4/table", payload, 15);
      if (!Boolean.TRUE.equals(result.get("ok"))) throw new AuthException(str(result, "error"));
      return result;
    }
  }
}
