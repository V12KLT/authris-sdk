# authv4 (Rust)

Authris license client. Add it with:

```sh
cargo add authv4
```

```rust
use authv4::Client;
use std::time::Duration;

fn main() {
    let mut app = Client::new("PASTE_PROJECT_ID", "https://your-server", None, None);
    if let Err(e) = app.init().and_then(|_| app.license("XXXX-XXXX-XXXX-XXXX", None).map(|_| ())) {
        println!("auth failed: {e}");
        return;
    }
    println!("licensed, remaining: {}", app.remaining);
    loop {
        std::thread::sleep(Duration::from_secs(60));
        match app.heartbeat() {
            Ok(left) => println!("heartbeat, remaining: {left}"),
            Err(e) => {
                println!("heartbeat failed: {e}");
                return;
            }
        }
    }
}
```

Full guide: [sdk/INTEGRATION.md](../INTEGRATION.md).
