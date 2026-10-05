#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "authv4.hpp"

static void check(const char* name, bool condition) {
  printf("%s %s\n", condition ? "PASS" : "FAIL", name);
  if (!condition) exit(1);
}

int main() {
  const char* base = getenv("AUTHV4_BASE");
  const char* pid = getenv("AUTHV4_PID");
  const char* key = getenv("AUTHV4_KEY");
  const char* key2 = getenv("AUTHV4_KEY2");
  const char* hwid = getenv("AUTHV4_HWID");
  try {
    authv4::Client app(pid, base);
    app.init();
    check("init", !app.server_key_.empty());
    authv4::License licensed = app.license(key, hwid);
    check("license", licensed.remaining > 80000);
    check("heartbeat", app.heartbeat() > 80000);
    check("info", app.info().get_str("status") == "active");
    check("variable", app.variable("offset") == "0x10");
    check("variables", app.variables()["offset"] == "0x10");
    std::vector<unsigned char> blob = app.file("app.bin");
    const char* secret = "sdk-file-secret-bytes";
    check("file", blob.size() == strlen(secret) && memcmp(blob.data(), secret, blob.size()) == 0);
    check("webhook", app.webhook("orders", "ping").get_num("status") == 200);
    check("table add", app.table("config", "add_row", 0, "{\"offset\":\"0x20\",\"label\":\"cpp\"}").get_bool("ok"));
    authv4::Json rows = app.table("config", "get_rows", 0, "");
    bool found = false;
    const authv4::Json* items = rows.find("rows");
    if (items && items->type == authv4::Json::Type::Arr) {
      for (const auto& row : items->arr) {
        const authv4::Json* data = row.find("data");
        if (data && data->get_str("label") == "cpp") found = true;
      }
    }
    check("table rows", found);

    authv4::Client user(pid, base);
    check("user register", user.user_register("cppuser", "DemoPass123!", key, hwid) == "cppuser");
    check("user login", user.user_login("cppuser", "DemoPass123!", hwid).remaining > 80000);
    authv4::Subscription sub = user.user_upgrade("cppuser", key2);
    check("user upgrade", sub.active && sub.remaining > 80000);
    check("user heartbeat", user.heartbeat() > 80000);
    check("user variable", user.variable("offset") == "0x10");

    authv4::Client bad(pid, base);
    try {
      bad.license("ZZZZ-9999-ZZZZ-9999", hwid);
      check("bad key rejected", false);
    } catch (const authv4::AuthError& err) {
      check("bad key rejected", strstr(err.what(), "Invalid key") != nullptr);
    }
    printf("CPP CHECKS PASSED\n");
  } catch (const authv4::AuthError& err) {
    printf("cpp check error: %s\n", err.what());
    return 1;
  }
}
