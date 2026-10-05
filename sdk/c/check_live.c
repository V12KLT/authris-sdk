#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "authv4.h"

static void check(const char *name, int condition) {
  printf("%s %s\n", condition ? "PASS" : "FAIL", name);
  if (!condition) exit(1);
}

int main(void) {
  const char *base = getenv("AUTHV4_BASE");
  const char *pid = getenv("AUTHV4_PID");
  const char *key = getenv("AUTHV4_KEY");
  const char *key2 = getenv("AUTHV4_KEY2");
  const char *hwid = getenv("AUTHV4_HWID");
  authv4_client app, user, bad;
  char status[32], value[4096], vars[8192], *table_resp = NULL;
  unsigned char *blob = NULL;
  size_t blob_len = 0;
  long hook_status = 0;

  authv4_setup(&app, pid, base, NULL, NULL);
  if (authv4_init(&app) != AUTHV4_OK) {
    printf("init error: %s\n", app.error);
    return 1;
  }
  check("init", app.server_key[0] != '\0');
  if (authv4_license(&app, key, hwid) != AUTHV4_OK) {
    printf("license error: %s\n", app.error);
    return 1;
  }
  check("license", app.remaining > 80000);
  if (authv4_heartbeat(&app) != AUTHV4_OK) {
    printf("heartbeat error: %s\n", app.error);
    return 1;
  }
  check("heartbeat", app.remaining > 80000);
  check("info", authv4_info(&app, status, sizeof(status), NULL) == AUTHV4_OK &&
                   strcmp(status, "active") == 0);
  check("variable",
        authv4_variable(&app, "offset", value, sizeof(value)) == AUTHV4_OK &&
            strcmp(value, "0x10") == 0);
  check("variables",
        authv4_variables(&app, vars, sizeof(vars)) == AUTHV4_OK &&
            authv4_json_get(vars, value, sizeof(value), "offset", NULL) == 0 &&
            strcmp(value, "0x10") == 0);
  check("file",
        authv4_file(&app, "app.bin", &blob, &blob_len) == AUTHV4_OK && blob_len == 21 &&
            memcmp(blob, "sdk-file-secret-bytes", 21) == 0);
  free(blob);
  check("webhook",
        authv4_webhook(&app, "orders", "ping", &hook_status) == AUTHV4_OK && hook_status == 200);
  check("table add", authv4_table(&app, "config", "add_row", 0, "{\"offset\":\"0x20\",\"label\":\"c\"}",
                                  100, &table_resp) == AUTHV4_OK);
  free(table_resp);
  table_resp = NULL;
  check("table rows", authv4_table(&app, "config", "get_rows", 0, NULL, 100, &table_resp) ==
                              AUTHV4_OK &&
                          authv4_json_has_pair(table_resp, "label", "c"));
  free(table_resp);

  authv4_setup(&user, pid, base, NULL, NULL);
  check("user register", authv4_user_register(&user, "cuser", "DemoPass123!", key, hwid) == AUTHV4_OK);
  check("user login", authv4_user_login(&user, "cuser", "DemoPass123!", hwid) == AUTHV4_OK &&
                         user.remaining > 80000);
  check("user upgrade", authv4_user_upgrade(&user, "cuser", key2) == AUTHV4_OK);
  check("user heartbeat", authv4_heartbeat(&user) == AUTHV4_OK && user.remaining > 80000);
  check("user variable",
        authv4_variable(&user, "offset", value, sizeof(value)) == AUTHV4_OK &&
            strcmp(value, "0x10") == 0);

  authv4_setup(&bad, pid, base, NULL, NULL);
  check("bad key rejected", authv4_license(&bad, "ZZZZ-9999-ZZZZ-9999", hwid) != AUTHV4_OK &&
                                 strstr(bad.error, "Invalid key") != NULL);
  printf("C CHECKS PASSED\n");
  return 0;
}
