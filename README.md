# Authris SDKs

Installable license-client SDKs for [Authris](https://github.com/V12KLT/authris)
(`authv4` 4.x, MIT). Eight languages, same API: init, license, heartbeat,
info, variables, files, webhooks, custom tables, user accounts.

| Language | Install |
|----------|---------|
| Python   | `pip install authv4` (`authv4[files]` for file downloads) |
| Node.js  | `npm install authv4` |
| Go       | `go get github.com/V12KLT/authris-sdk/sdk/go/v4` |
| Java     | JitPack `com.github.V12KLT:authris-sdk:v4.0.0` |
| Rust     | `cargo add authv4` |
| C#       | `dotnet add package AuthV4` |
| C++      | CMake FetchContent, tag `v4.0.0` (see `sdk/cpp/README.md`) |
| C        | CMake FetchContent, tag `v4.0.0` (see `sdk/c/README.md`) |

Each `sdk/<lang>/` folder has a README with a working quickstart plus an
`example`. Start with [sdk/INTEGRATION.md](sdk/INTEGRATION.md).

## Releasing

Bump the version in every manifest (`pyproject.toml`, `package.json`,
`AuthV4.csproj`, `Cargo.toml`), commit, then:

```
git tag v4.0.0
git tag sdk/go/v4.0.0
git push --tags
```

The `v*` tag triggers the release workflow (PyPI, npm, crates.io, NuGet).
Go, JitPack, and FetchContent resolve straight from the tags.
