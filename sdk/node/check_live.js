const { AuthError, Client } = require("./authv4");

const BASE = process.env.AUTHV4_BASE;
const PID = process.env.AUTHV4_PID;
const KEY = process.env.AUTHV4_KEY;
const KEY2 = process.env.AUTHV4_KEY2;
const HWID = process.env.AUTHV4_HWID;

function check(name, condition) {
  console.log((condition ? "PASS " : "FAIL ") + name);
  if (!condition) {
    console.error("check failed: " + name);
    process.exit(1);
  }
}

async function main() {
  const app = new Client({ projectId: PID, baseUrl: BASE });
  await app.init();
  check("init", !!app.serverKey);
  const licensed = await app.license(KEY, HWID);
  check("license", licensed.remaining > 80000);
  check("heartbeat", (await app.heartbeat()) > 80000);
  check("info", (await app.info()).status === "active");
  check("variable", (await app.variable("offset")) === "0x10");
  check("variables", (await app.variable()).offset === "0x10");
  check("file", (await app.file("app.bin")).equals(Buffer.from("sdk-file-secret-bytes")));
  check("webhook", (await app.webhook("orders", "ping")).status === 200);
  check("table add", (await app.table("config", "add_row", { data: { offset: "0x20", label: "node" } })).ok === true);
  const rows = (await app.table("config", "get_rows")).rows;
  check("table rows", rows.some((r) => r.data && r.data.label === "node"));

  const user = new Client({ projectId: PID, baseUrl: BASE });
  check("user register", (await user.userRegister("nodeuser", "DemoPass123!", KEY)) === "nodeuser");
  check("user login", (await user.userLogin("nodeuser", "DemoPass123!", HWID)).remaining > 80000);
  const sub = await user.userUpgrade("nodeuser", KEY2);
  check("user upgrade", sub.active === true && sub.remaining > 80000);
  check("user heartbeat", (await user.heartbeat()) > 80000);
  check("user variable", (await user.variable("offset")) === "0x10");

  const bad = new Client({ projectId: PID, baseUrl: BASE });
  try {
    await bad.license("ZZZZ-9999-ZZZZ-9999", HWID);
    check("bad key rejected", false);
  } catch (err) {
    check("bad key rejected", err instanceof AuthError && err.message.includes("Invalid key"));
  }
  console.log("NODE CHECKS PASSED");
}

main().catch((err) => {
  console.error("node check error:", err);
  process.exit(1);
});
