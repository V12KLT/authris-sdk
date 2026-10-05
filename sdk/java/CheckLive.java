import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CheckLive {
  static void check(String name, boolean condition) {
    System.out.println((condition ? "PASS " : "FAIL ") + name);
    if (!condition) System.exit(1);
  }

  @SuppressWarnings("unchecked")
  public static void main(String[] args) throws Exception {
    String base = System.getenv("AUTHV4_BASE");
    String pid = System.getenv("AUTHV4_PID");
    String key = System.getenv("AUTHV4_KEY");
    String key2 = System.getenv("AUTHV4_KEY2");
    String hwid = System.getenv("AUTHV4_HWID");

    AuthV4.Client app = new AuthV4.Client(pid, base, null, null);
    app.init();
    check("init", app.serverKey != null && !app.serverKey.isEmpty());
    AuthV4.License licensed = app.license(key, hwid);
    check("license", licensed.remaining > 80000);
    check("heartbeat", app.heartbeat() > 80000);
    check("info", "active".equals(app.info().get("status")));
    check("variable", "0x10".equals(app.variable("offset")));
    check("variables", "0x10".equals(app.variables().get("offset")));
    check("file", Arrays.equals(app.file("app.bin"), "sdk-file-secret-bytes".getBytes()));
    check("webhook", ((Number) app.webhook("orders", "ping").get("status")).intValue() == 200);
    Map<String, Object> row = new LinkedHashMap<>();
    row.put("offset", "0x20");
    row.put("label", "java");
    check("table add", Boolean.TRUE.equals(app.table("config", "add_row", null, row, 100).get("ok")));
    List<Object> rows = (List<Object>) app.table("config", "get_rows", null, null, 100).get("rows");
    boolean found = false;
    for (Object item : rows) {
      Object data = ((Map<String, Object>) item).get("data");
      if (data instanceof Map && "java".equals(((Map<String, Object>) data).get("label"))) found = true;
    }
    check("table rows", found);

    AuthV4.Client user = new AuthV4.Client(pid, base, null, null);
    check("user register", "javauser".equals(user.userRegister("javauser", "DemoPass123!", key, null)));
    check("user login", user.userLogin("javauser", "DemoPass123!", hwid).remaining > 80000);
    Map<String, Object> sub = user.userUpgrade("javauser", key2);
    check("user upgrade", Boolean.TRUE.equals(sub.get("active")) && ((Number) sub.get("remaining")).longValue() > 80000);
    check("user heartbeat", user.heartbeat() > 80000);
    check("user variable", "0x10".equals(user.variable("offset")));

    AuthV4.Client bad = new AuthV4.Client(pid, base, null, null);
    try {
      bad.license("ZZZZ-9999-ZZZZ-9999", hwid);
      check("bad key rejected", false);
    } catch (AuthV4.AuthException e) {
      check("bad key rejected", e.getMessage().contains("Invalid key"));
    }
    System.out.println("JAVA CHECKS PASSED");
  }
}
