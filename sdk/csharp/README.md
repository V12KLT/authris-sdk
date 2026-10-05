# AuthV4 (C#)

Authris license client for .NET 8+. Framework only —
no packages.

```sh
dotnet add package AuthV4
```

```csharp
using AuthV4;

using var app = new Client("PASTE_PROJECT_ID", "https://your-server");
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
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
