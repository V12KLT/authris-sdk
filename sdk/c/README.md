# authv4 (C)

Authris license client: two files, no build step. Needs libcurl
and OpenSSL. Fetch it with CMake:

```cmake
include(FetchContent)
FetchContent_Declare(
  authv4
  GIT_REPOSITORY https://github.com/V12KLT/authris-sdk.git
  GIT_TAG        v4.0.1
)
FetchContent_MakeAvailable(authv4)

target_include_directories(myapp PRIVATE ${authv4_SOURCE_DIR}/sdk/c)
target_sources(myapp PRIVATE ${authv4_SOURCE_DIR}/sdk/c/authv4.c)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(myapp PRIVATE CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
```

Or just copy `authv4.h` and `authv4.c` next to your code.

```c
#include "authv4.h"

authv4_client app;
authv4_setup(&app, "PASTE_PROJECT_ID", "https://your-server", NULL, NULL);
if (authv4_init(&app) != 0) { printf("auth failed\n"); return 1; }
if (authv4_license(&app, "XXXX-XXXX-XXXX-XXXX", NULL) != 0) { printf("auth failed\n"); return 1; }
printf("licensed, remaining: %lld\n", app.remaining);
for (;;) {
  sleep(60);
  if (authv4_heartbeat(&app) != 0) { printf("heartbeat failed\n"); return 1; }
  printf("heartbeat, remaining: %lld\n", app.remaining);
}
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
