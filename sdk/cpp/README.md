# authv4 (C++)

Authris license client: one header (`authv4.hpp`, C++17).
Needs libcurl and OpenSSL. Fetch it with CMake:

```cmake
include(FetchContent)
FetchContent_Declare(
  authv4
  GIT_REPOSITORY https://github.com/V12KLT/authris-sdk.git
  GIT_TAG        v4.0.1
)
FetchContent_MakeAvailable(authv4)

target_include_directories(myapp PRIVATE ${authv4_SOURCE_DIR}/sdk/cpp)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(myapp PRIVATE CURL::libcurl OpenSSL::SSL OpenSSL::Crypto)
```

Or just copy `authv4.hpp` next to your code.

```cpp
#include "authv4.hpp"

int main() {
  authv4::Client app("PASTE_PROJECT_ID", "https://your-server");
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
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
