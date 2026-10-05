# authv4 (Node.js)

Authris license client for Node 18+. Standard library only —
zero dependencies.

```sh
npm install authv4
```

```js
const { Client } = require("authv4");

async function main() {
  const app = new Client({ projectId: "PASTE_PROJECT_ID", baseUrl: "https://your-server" });
  await app.init();
  await app.license("XXXX-XXXX-XXXX-XXXX");
  console.log("licensed, remaining:", app.remaining);
  for (;;) {
    await new Promise((r) => setTimeout(r, 60000));
    console.log("heartbeat, remaining:", await app.heartbeat());
  }
}

main().catch((err) => {
  console.error("auth failed:", err.message);
  process.exit(1);
});
```

ES modules: `import pkg from "authv4"; const { Client } = pkg;`

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
