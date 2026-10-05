# AuthV4 (Java)

Authris license client for JDK 11+. No dependencies.
Install via [JitPack](https://jitpack.io) (no registry account needed):

```gradle
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.V12KLT:authris-sdk:v4.0.1'
}
```

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
  <groupId>com.github.V12KLT</groupId>
  <artifactId>authris</artifactId>
  <version>v4.0.1</version>
</dependency>
```

```java
AuthV4.Client app = new AuthV4.Client("PASTE_PROJECT_ID", "https://your-server", null, null);
try {
  app.init();
  AuthV4.License licensed = app.license("XXXX-XXXX-XXXX-XXXX", null);
  System.out.println("licensed, remaining: " + licensed.remaining);
  for (;;) {
    Thread.sleep(60000);
    System.out.println("heartbeat, remaining: " + app.heartbeat());
  }
} catch (AuthV4.AuthException e) {
  System.out.println("auth failed: " + e.getMessage());
}
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
