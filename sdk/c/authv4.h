#ifndef AUTHV4_H
#define AUTHV4_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AUTHV4_OK 0
#define AUTHV4_ERR -1

typedef struct {
  char project_id[40];
  char base_url[256];
  char app_hash[129];
  char server_key[129];
  char session[65];
  char key[129];
  char hwid[129];
  char username[64];
  long long expires;
  long long remaining;
  char challenge_id[33];
  char challenge[65];
  char error[256];
} authv4_client;

void authv4_setup(authv4_client *c, const char *project_id, const char *base_url,
                  const char *app_hash, const char *server_key);

int authv4_init(authv4_client *c);

int authv4_license(authv4_client *c, const char *key, const char *hwid);

int authv4_user_register(authv4_client *c, const char *username, const char *password, const char *key, const char *hwid);

int authv4_user_login(authv4_client *c, const char *username, const char *password, const char *hwid);

int authv4_user_redeem(authv4_client *c, const char *username, const char *password, const char *key);
int authv4_user_upgrade(authv4_client *c, const char *username, const char *key);

int authv4_heartbeat(authv4_client *c);

int authv4_info(authv4_client *c, char *status_out, size_t status_len, long long *remaining_out);

int authv4_variable(authv4_client *c, const char *name, char *value_out, size_t value_len);

int authv4_variables(authv4_client *c, char *json_out, size_t json_len);

int authv4_file(authv4_client *c, const char *name, unsigned char **data_out, size_t *len_out);

int authv4_webhook(authv4_client *c, const char *name, const char *data, long *status_out);

int authv4_table(authv4_client *c, const char *table, const char *op, long long id,
                 const char *data_json, long long limit, char **resp_out);

int authv4_machine_hwid(char *out, size_t len);

int authv4_sha256_file(const char *path, char *out_hex);

int authv4_json_get(const char *json, char *out, size_t outlen, ...);
int authv4_json_get_int(const char *json, long long *out, ...);
int authv4_json_is_true(const char *json, ...);
int authv4_json_has_pair(const char *json, const char *key, const char *value);

#ifdef __cplusplus
}
#endif

#endif
