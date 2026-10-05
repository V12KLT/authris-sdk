using AuthV4;

using var app = new Client("PASTE_PROJECT_ID", "http://127.0.0.1:8080");
try
{
    await app.InitAsync();
    var licensed = await app.LicenseAsync("XXXX-XXXX-XXXX-XXXX");
    Console.WriteLine("licensed, remaining: " + licensed.Remaining);
    for (;;)
    {
        await Task.Delay(TimeSpan.FromSeconds(60));
        Console.WriteLine("heartbeat, remaining: " + await app.HeartbeatAsync());
    }
}
catch (AuthException e)
{
    Console.WriteLine("auth failed: " + e.Message);
}
