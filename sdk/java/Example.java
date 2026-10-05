public class Example {
  public static void main(String[] args) throws Exception {
    AuthV4.Client app = new AuthV4.Client("PASTE_PROJECT_ID", "http://127.0.0.1:8080", null, null);
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
  }
}
