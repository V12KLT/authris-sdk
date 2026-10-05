using System.Diagnostics;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthV4;

public class AuthException : Exception
{
    public AuthException(string message) : base(message) { }
}

public record LicenseResult(long Expires, long Remaining);

public record SubscriptionResult(long Expires, long Remaining, bool Active);

public class Client : IDisposable
{
    public string ProjectId { get; }
    public string BaseUrl { get; }
    public string? AppHash { get; set; }
    public string? ServerKey { get; set; }
    public string? Session { get; private set; }
    public string? Key { get; private set; }
    public string? Hwid { get; private set; }
    public string? Username { get; private set; }
    public long Expires { get; private set; }
    public long Remaining { get; private set; } = -1;

    string? _challengeId;
    string? _challenge;
    readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(65) };

    public Client(string projectId, string baseUrl, string? appHash = null, string? serverKey = null)
    {
        ProjectId = projectId;
        BaseUrl = baseUrl.TrimEnd('/');
        AppHash = appHash;
        ServerKey = serverKey;
    }

    public void Dispose() => _http.Dispose();

    static string HmacHex(string key, string message)
    {
        using var mac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(mac.ComputeHash(Encoding.UTF8.GetBytes(message))).ToLower();
    }

    static byte[] Unhex(string text) => Convert.FromHexString(text);

    static string Str(JsonElement el, string name)
    {
        if (el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String)
            return v.GetString() ?? "";
        return "";
    }

    static long Num(JsonElement el, string name)
    {
        if (el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number)
            return v.GetInt64();
        return 0;
    }

    public static bool VerifySignature(string publicHex, string data, string signatureHex)
    {
        try
        {
            var key = Unhex(publicHex);
            var sig = Unhex(signatureHex);
            if (key.Length != 64 || sig.Length != 64) return false;
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = key[..32], Y = key[32..] },
            });
            return ecdsa.VerifyData(
                Encoding.UTF8.GetBytes(data), sig,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch
        {
            return false;
        }
    }

    public static string MachineHwid()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                var guid = key?.GetValue("MachineGuid")?.ToString();
                if (!string.IsNullOrEmpty(guid)) return guid!;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var id = File.ReadAllText("/etc/machine-id").Trim();
                if (id.Length > 0) return id;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var psi = new ProcessStartInfo("ioreg", "-rd1 -c IOPlatformExpertDevice")
                {
                    RedirectStandardOutput = true, UseShellExecute = false,
                };
                using var proc = Process.Start(psi)!;
                var lines = proc.StandardOutput.ReadToEnd().Split('\n');
                proc.WaitForExit();
                foreach (var line in lines)
                {
                    if (line.Contains("IOPlatformUUID"))
                    {
                        var parts = line.Split('"');
                        return parts[^2];
                    }
                }
            }
        }
        catch { }
        var raw = Environment.MachineName + RuntimeInformation.OSDescription;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLower()[..32];
    }

    public static string Sha256File(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLower();
    }

    async Task<JsonElement> Post(string path, object payload, int timeoutSec = 15)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        HttpResponseMessage res;
        try
        {
            res = await _http.PostAsJsonAsync(BaseUrl + path, payload, cts.Token);
        }
        catch (Exception e)
        {
            throw new AuthException("Request failed: " + e.Message);
        }
        if (!res.IsSuccessStatusCode)
            throw new AuthException("Request failed: HTTP " + (int)res.StatusCode);
        using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(cts.Token), cancellationToken: cts.Token);
        return doc.RootElement.Clone();
    }

    async Task<JsonElement> Get(string path, int timeoutSec = 15)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        HttpResponseMessage res;
        try
        {
            res = await _http.GetAsync(BaseUrl + path, cts.Token);
        }
        catch (Exception e)
        {
            throw new AuthException("Request failed: " + e.Message);
        }
        if (!res.IsSuccessStatusCode)
            throw new AuthException("Request failed: HTTP " + (int)res.StatusCode);
        using var doc = await JsonDocument.ParseAsync(await res.Content.ReadAsStreamAsync(cts.Token), cancellationToken: cts.Token);
        return doc.RootElement.Clone();
    }

    static bool RotationOk(JsonElement el, string current, string pinned)
    {
        if (!el.TryGetProperty("rotation", out var rotation) || rotation.ValueKind != JsonValueKind.Object)
            return false;
        if (!rotation.TryGetProperty("new_key", out var nk) || nk.GetString() != current)
            return false;
        if (!rotation.TryGetProperty("signature", out var sig) || sig.ValueKind != JsonValueKind.String)
            return false;
        try { return VerifySignature(pinned, "ROTATE:" + current, sig.GetString()!); }
        catch { return false; }
    }

    static void RequireOk(JsonElement el, string fallback)
    {
        if (!el.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
            throw new AuthException(Str(el, "error") is string e && e.Length > 0 ? e : fallback);
    }

    public async Task InitAsync()
    {
        var payload = await Get("/v4/server-key");
        var fetched = Str(payload, "server_key");
        if (fetched.Length == 0) throw new AuthException("Server key missing");
        if (!string.IsNullOrEmpty(ServerKey) && ServerKey != fetched && !RotationOk(payload, fetched, ServerKey))
            throw new AuthException("Server key mismatch (get the current key from GET /v4/server-key or the dashboard Setup page)");
        ServerKey = fetched;
        var result = await Post("/v4/init", new { project_id = ProjectId });
        RequireOk(result, "Init failed");
        _challengeId = Str(result, "challenge_id");
        _challenge = Str(result, "challenge");
    }

    public async Task<LicenseResult> LicenseAsync(string licenseKey, string? hwid = null)
    {
        if (_challenge is null) await InitAsync();
        var useHwid = string.IsNullOrEmpty(hwid) ? MachineHwid() : hwid;
        var challenge = _challenge!;
        var payload = new Dictionary<string, object>
        {
            ["project_id"] = ProjectId,
            ["key"] = licenseKey,
            ["hwid"] = useHwid,
            ["challenge_id"] = _challengeId!,
            ["signature"] = HmacHex(licenseKey, challenge),
        };
        if (!string.IsNullOrEmpty(AppHash)) payload["app_hash"] = AppHash;
        _challenge = null;
        _challengeId = null;
        var result = await Post("/v4/license", payload);
        RequireOk(result, "License failed");
        var proofBase = challenge + "|" + Str(result, "session");
        if (HmacHex(licenseKey, proofBase) != Str(result, "server_proof"))
            throw new AuthException("Server proof mismatch");
        if (!string.IsNullOrEmpty(ServerKey) && !VerifySignature(ServerKey, proofBase, Str(result, "signature")))
            throw new AuthException("Server signature mismatch");
        Session = Str(result, "session");
        Key = licenseKey;
        Hwid = useHwid;
        Expires = Num(result, "expires");
        Remaining = result.TryGetProperty("remaining", out _) ? Num(result, "remaining") : -1;
        return new LicenseResult(Expires, Remaining);
    }

    public async Task<string> UserRegisterAsync(string username, string password, string licenseKey, string? hwid = null)
    {
        var payload = new Dictionary<string, object>
        {
            ["project_id"] = ProjectId,
            ["username"] = username,
            ["password"] = password,
            ["key"] = licenseKey,
        };
        if (!string.IsNullOrEmpty(hwid)) payload["hwid"] = hwid;
        var result = await Post("/v4/user/register", payload);
        RequireOk(result, "Register failed");
        return Str(result, "username");
    }

    public async Task<LicenseResult> UserLoginAsync(string username, string password, string? hwid = null)
    {
        if (string.IsNullOrEmpty(ServerKey)) await InitAsync();
        var useHwid = string.IsNullOrEmpty(hwid) ? MachineHwid() : hwid;
        var result = await Post("/v4/user/login", new { project_id = ProjectId, username, password, hwid = useHwid });
        RequireOk(result, "Login failed");
        var session = Str(result, "session");
        if (!string.IsNullOrEmpty(ServerKey) && !VerifySignature(ServerKey, "user|" + session, Str(result, "signature")))
            throw new AuthException("Server signature mismatch");
        Session = session;
        Key = password;
        Hwid = useHwid;
        Username = username;
        if (result.TryGetProperty("subscription", out var sub))
        {
            Expires = Num(sub, "expires");
            Remaining = Num(sub, "remaining");
        }
        return new LicenseResult(Expires, Remaining);
    }

    public async Task<SubscriptionResult> UserRedeemAsync(string username, string password, string licenseKey)
    {
        var result = await Post("/v4/user/redeem", new { project_id = ProjectId, username, password, key = licenseKey });
        RequireOk(result, "Redeem failed");
        var sub = result.GetProperty("subscription");
        return new SubscriptionResult(Num(sub, "expires"), Num(sub, "remaining"),
            sub.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True);
    }

    public async Task<SubscriptionResult> UserUpgradeAsync(string username, string licenseKey)
    {
        var result = await Post("/v4/user/upgrade", new { project_id = ProjectId, username, key = licenseKey });
        RequireOk(result, "Upgrade failed");
        var sub = result.GetProperty("subscription");
        return new SubscriptionResult(Num(sub, "expires"), Num(sub, "remaining"),
            sub.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True);
    }

    public async Task<long> HeartbeatAsync()
    {
        if (Session is null || Key is null) throw new AuthException("Not licensed");
        var result = await Post("/v4/heartbeat", new { session = Session, key = Key });
        RequireOk(result, "Heartbeat failed");
        var left = Num(result, "remaining");
        var proofBase = $"VERIFY:{ProjectId}:{left}";
        if (HmacHex(Key, proofBase) != Str(result, "proof"))
            throw new AuthException("Heartbeat proof mismatch");
        if (!string.IsNullOrEmpty(ServerKey) && !VerifySignature(ServerKey, proofBase, Str(result, "signature")))
            throw new AuthException("Heartbeat signature mismatch");
        Remaining = left;
        return left;
    }

    public async Task<JsonElement> InfoAsync()
    {
        if (Key is null) throw new AuthException("Not licensed");
        var useHwid = string.IsNullOrEmpty(Hwid) ? MachineHwid() : Hwid;
        var result = await Post("/v4/info", new { project_id = ProjectId, key = Key, hwid = useHwid });
        RequireOk(result, "Info failed");
        return result;
    }

    public async Task<Dictionary<string, string>> VariablesAsync()
    {
        if (Session is null || Key is null) throw new AuthException("Not licensed");
        var result = await Post("/v4/variable", new { session = Session, key = Key });
        RequireOk(result, "Variable failed");
        var map = new Dictionary<string, string>();
        if (result.TryGetProperty("variables", out var vars) && vars.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in vars.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                    map[prop.Name] = prop.Value.GetString()!;
            }
        }
        return map;
    }

    public async Task<string> VariableAsync(string name)
    {
        if (Session is null || Key is null) throw new AuthException("Not licensed");
        var result = await Post("/v4/variable", new { session = Session, key = Key, name });
        RequireOk(result, "Variable failed");
        return Str(result, "value");
    }

    public async Task<byte[]> FileAsync(string name)
    {
        if (Session is null || Key is null) throw new AuthException("Not licensed");
        var result = await Post("/v4/file", new { session = Session, key = Key, name }, 60);
        RequireOk(result, "File failed");
        try
        {
            var nonceHex = Str(result, "nonce");
            var fileKey = Unhex(HmacHex(Key, "FILE_KEY:" + nonceHex));
            var nonce = Unhex(nonceHex);
            var content = Convert.FromBase64String(Str(result, "data"));
            var tag = Unhex(Str(result, "tag"));
            var plain = new byte[content.Length];
            using var gcm = new AesGcm(fileKey, 16);
            gcm.Decrypt(nonce, content, tag, plain, Encoding.UTF8.GetBytes(ProjectId));
            if (Convert.ToHexString(SHA256.HashData(plain)).ToLower() != Str(result, "hash"))
                throw new AuthException("File hash mismatch");
            return plain;
        }
        catch (AuthException) { throw; }
        catch (Exception e) { throw new AuthException("File decrypt failed: " + e.Message); }
    }

    public async Task<JsonElement> WebhookAsync(string name, string data = "")
    {
        if (Session is null || Key is null) throw new AuthException("Not licensed");
        var result = await Post("/v4/webhook", new { session = Session, key = Key, name, data }, 30);
        RequireOk(result, "Webhook failed");
        return result;
    }

    public async Task<JsonElement> TableAsync(string table, string op, long? id = null, object? data = null, int limit = 100)
    {
        if (Session is null || Key is null) throw new AuthException("Not licensed");
        var payload = new Dictionary<string, object>
        {
            ["session"] = Session,
            ["key"] = Key,
            ["table"] = table,
            ["op"] = op,
            ["limit"] = limit,
        };
        if (id is not null) payload["id"] = id;
        if (data is not null) payload["data"] = data;
        var result = await Post("/v4/table", payload);
        RequireOk(result, "Table failed");
        return result;
    }
}
