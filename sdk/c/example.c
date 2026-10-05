#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "authv4.h"

int main(void) {
  authv4_client app;
  authv4_setup(&app, "PASTE_PROJECT_ID", "http://127.0.0.1:8080", NULL, NULL);
  if (authv4_init(&app) != AUTHV4_OK || authv4_license(&app, "XXXX-XXXX-XXXX-XXXX", NULL) != AUTHV4_OK) {
    printf("auth failed: %s\n", app.error);
    return 1;
  }
  printf("licensed, remaining: %lld\n", app.remaining);
  for (;;) {
#ifdef _WIN32
    Sleep(60000);
#else
    sleep(60);
#endif
    if (authv4_heartbeat(&app) != AUTHV4_OK) {
      printf("heartbeat failed: %s\n", app.error);
      return 1;
    }
    printf("heartbeat, remaining: %lld\n", app.remaining);
  }
}
