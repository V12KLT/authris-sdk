using AuthV4;
using System.Text;

var baseUrl = Environment.GetEnvironmentVariable("AUTHV4_BASE")!;
var pid = Environment.GetEnvironmentVariable("AUTHV4_PID")!;
var key = Environment.GetEnvironmentVariable("AUTHV4_KEY")!;
var key2 = Environment.GetEnvironmentVariable("AUTHV4_KEY2")!;
var hwid = Environment.GetEnvironmentVariable("AUTHV4_HWID")!;

void Check(string name, bool condition)
{
    Console.WriteLine((condition ? "PASS " : "FAIL ") + name);
    if (!condition) Environment.Exit(1);
}

using var app = new Client(pid, baseUrl);
await app.InitAsync();
Check("init", !string.IsNullOrEmpty(app.ServerKey));
var licensed = await app.LicenseAsync(key, hwid);
Check("license", licensed.Remaining > 80000);
Check("heartbeat", await app.HeartbeatAsync() > 80000);
Check("info", (await app.InfoAsync()).GetProperty("status").GetString() == "active");
Check("variable", await app.VariableAsync("offset") == "0x10");
Check("variables", (await app.VariablesAsync())["offset"] == "0x10");
Check("file", (await app.FileAsync("app.bin")).SequenceEqual(Encoding.UTF8.GetBytes("sdk-file-secret-bytes")));
Check("webhook", (await app.WebhookAsync("orders", "ping")).GetProperty("status").GetInt32() == 200);
var added = await app.TableAsync("config", "add_row", data: new { offset = "0x20", label = "csharp" });
Check("table add", added.GetProperty("ok").GetBoolean());
var rows = (await app.TableAsync("config", "get_rows")).GetProperty("rows");
var found = rows.EnumerateArray().Any(r => r.GetProperty("data").GetProperty("label").GetString() == "csharp");
Check("table rows", found);

using var user = new Client(pid, baseUrl);
Check("user register", await user.UserRegisterAsync("sharpuser", "DemoPass123!", key) == "sharpuser");
Check("user login", (await user.UserLoginAsync("sharpuser", "DemoPass123!", hwid)).Remaining > 80000);
var sub = await user.UserUpgradeAsync("sharpuser", key2);
Check("user upgrade", sub.Active && sub.Remaining > 80000);
Check("user heartbeat", await user.HeartbeatAsync() > 80000);
Check("user variable", await user.VariableAsync("offset") == "0x10");

using var bad = new Client(pid, baseUrl);
try
{
    await bad.LicenseAsync("ZZZZ-9999-ZZZZ-9999", hwid);
    Check("bad key rejected", false);
}
catch (AuthException e)
{
    Check("bad key rejected", e.Message.Contains("Invalid key"));
}
Console.WriteLine("CSHARP CHECKS PASSED");
