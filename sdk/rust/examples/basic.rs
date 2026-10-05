use authv4::Client;
use std::time::Duration;

fn main() {
    let mut app = Client::new("PASTE_PROJECT_ID", "http://127.0.0.1:8080", None, None);
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
