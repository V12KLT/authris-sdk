const { Client } = require("./authv4");

async function main() {
  const app = new Client({ projectId: "PASTE_PROJECT_ID", baseUrl: "http://127.0.0.1:8080" });
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
