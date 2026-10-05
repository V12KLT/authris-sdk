# Authris Integration Guide

Three steps: init, license, heartbeat. Every SDK below implements the
full API: init, license, heartbeat, info, variables, file download,
webhooks, custom tables, HWID detection, and server-signature checks.

## SDKs

| Language   | Install                                                        | Needs                       |
| ---------- | -------------------------------------------------------------- | --------------------------- |
| Python     | `pip install authv4` (`authv4[files]` for file downloads)      | Python 3.9+                 |
| Node.js    | `npm install authv4`                                           | Node 18+, nothing else      |
| Go         | `go get github.com/V12KLT/authris-sdk/sdk/go/v4`                    | Go 1.21+, stdlib only       |
| Java       | JitPack: `com.github.V12KLT:authris-sdk:v4.0.0`                    | JDK 11+, no dependencies    |
| Rust       | `cargo add authv4`                                             | Cargo                       |
| C#         | `dotnet add package AuthV4`                                    | .NET 8, no packages         |
| C++        | CMake FetchContent (`v4.0.0` tag)                              | libcurl + OpenSSL           |
| C          | CMake FetchContent (`v4.0.0` tag)                              | libcurl + OpenSSL           |

Prefer the package install. Without package access, the dashboard
Setup page lets end users download each SDK file with one click
(files live next to the package manifests: `sdk/<lang>/`).

Each SDK folder has an `example` plus a live check. Run every check
against a throwaway server with:

```
python sdk/live/run_all.py
```

Releasing a new SDK version: bump the version in every manifest
(`pyproject.toml`, `package.json`, `AuthV4.csproj`, `Cargo.toml`),
commit, then tag it (`git tag v4.0.0 && git push --tags`). The tag
triggers `.github/workflows/release-sdks.yml`, which publishes to
PyPI, npm, crates.io, and NuGet. Go, JitPack, and FetchContent
resolve straight from the tag, so they need no registry step.

## 1. Init

```python
from authv4 import Client

app = Client(project_id="PASTE_PROJECT_ID", base_url="https://your-server")
app.init()
```

`init` fetches a one-time challenge and the server public key.
Pass `server_key="..."` to pin a known key instead of trusting
the first connection.

## 2. License

```python
app.license(key="XXXX-XXXX-XXXX-XXXX")
```

The client signs the challenge with HMAC-SHA256, so the raw key is
sent once and every later answer is verified. A machine id is picked
up automatically; pass `hwid="..."` to override it. The first license
call binds the key to that machine and starts the duration clock.

Optional: pass `app_hash=sha256_file("myapp.exe")` to the Client so
the server only licenses untampered binaries. Register the hash in
the dashboard first.

## 3. Heartbeat

```python
while True:
    time.sleep(60)
    app.heartbeat()
```

Heartbeat proves the session is alive and re-checks bans, pause,
expiry, and HWID on the server. If it raises, stop the app and ask
the user to restart (the session was killed, expired, or banned).

## Extras

```python
app.variable("offset")
app.file("app.bin")
app.webhook("orders", data="ping")
app.table("config", "get_rows")
```

## User Accounts

```python
app.user_register("gamer1", "DemoPass123!", "XXXX-XXXX-XXXX-XXXX")
app.user_login("gamer1", "DemoPass123!")
app.user_upgrade("gamer1", "YYYY-YYYY-YYYY-YYYY")
```

Registering consumes the key and adds its full duration to the
new account's subscription. `user_upgrade` tops up with another
key and needs no password. After `user_login`, heartbeat and
every Extras call above work unchanged (the SDK uses the
password where the key goes).

## Prebuilt Binaries

| Binary           | Build from repo root                        |
| ---------------- | ------------------------------------------- |
| `AuthV4.dll`     | `powershell sdk/csharp/build_dll.ps1`       |
| `authv4.dll`     | `sdk/c/build_dll.bat` (needs MSVC + vcpkg curl/OpenSSL) |

Both land in `sdk/dist/`. The C# DLL targets net8.0 and has
no dependencies. The C DLL exports the plain C ABI from
`sdk/c/authv4.h`, so C, C++, Rust, Go, Python (ctypes), and C#
(P/Invoke) can all load it. Prefer the DLL over pasting source:
the crypto stays in one compiled unit that is harder to tamper
with than code sitting next to the app.

## Locking Clients Down

The SDKs verify the server on every step and throw when anything
fails: proof mismatch, signature mismatch, ban, pause, expiry,
HWID change. Treat every throw as "stop the app", never swallow
one and continue.

No server can prove which client code is running, so the binding
is: TLS + pinned server key + binary hash.

1. Pin `server_key` in the app (copy it from the dashboard
   Setup page, step 2, or `GET /v4/server-key`). Without
   pinning, the first connection is trust-on-first-use. A
   "Server key mismatch" error means the app holds a stale key:
   copy the fresh one.

## Rotating The Server Key

Rotate when the private key may have leaked, not on a timer:
scheduled rotation only manufactures mismatch errors. The
retired key signs an endorsement of its successor, so updated
SDKs verify the rotation proof and keep working with no client
update required.

1. Copy `backend/data/signing_private.pem` to
   `backend/data/signing_previous.pem` (keep it `0600`: while
   the overlap lasts it can endorse keys, so guard it like the
   live one).
2. Delete `backend/data/signing_private.pem` and restart. The
   server generates a fresh key and serves the old key's
   endorsement alongside it.
3. Ship the new pinned key to your apps at leisure. Clients
   pinning the old key verify the proof and keep working.
4. Once every client carries the new key, delete
   `signing_previous.pem` and restart to close the overlap.

Wiping the data dir without step 1 regenerates the key with no
proof, so every pinned client mismatches until updated.
2. Register the app's SHA256 in the dashboard Hashes tab. From
   that moment the server refuses any license call without a
   matching `app_hash`, which only genuine untampered builds
   send.
3. Heartbeat every 1-5 minutes. Killed or expired sessions stop
   working within one interval.

## Moving From The Socket Version

| Old (TCP 3389)        | New (HTTPS)                    |
| --------------------- | ------------------------------ |
| Connect + handshake   | POST /v4/init                  |
| PROJECT_ID\|KEY\|HWID | POST /v4/license               |
| CHALLENGE/RESPONSE    | HMAC signature field           |
| verify_client_session | POST /v4/heartbeat             |
| get_key_info          | POST /v4/info                  |
| client_custom_data    | POST /v4/variable, /v4/table   |
| client_file_download  | POST /v4/file                  |
| client_webhook_call   | POST /v4/webhook               |

No ports to open, no TLS fingerprints to pin, no persistent
connection to hold. Any language with HTTPS and HMAC works.
