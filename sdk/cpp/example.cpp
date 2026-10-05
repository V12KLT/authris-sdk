#include <chrono>
#include <cstdio>
#include <thread>

#include "authv4.hpp"

int main() {
  authv4::Client app("PASTE_PROJECT_ID", "http://127.0.0.1:8080");
  try {
    app.init();
    authv4::License licensed = app.license("XXXX-XXXX-XXXX-XXXX");
    printf("licensed, remaining: %lld\n", licensed.remaining);
    for (;;) {
      std::this_thread::sleep_for(std::chrono::seconds(60));
      printf("heartbeat, remaining: %lld\n", app.heartbeat());
    }
  } catch (const authv4::AuthError& err) {
    printf("auth failed: %s\n", err.what());
    return 1;
  }
}
