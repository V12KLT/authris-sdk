use authv4::Client;
use std::env;

fn check(name: &str, condition: bool) {
    if condition {
        println!("PASS {name}");
    } else {
        println!("FAIL {name}");
        std::process::exit(1);
    }
}

fn getenv(name: &str) -> String {
    env::var(name).unwrap_or_default()
}

fn main() {
    let base = getenv("AUTHV4_BASE");
    let pid = getenv("AUTHV4_PID");
    let key = getenv("AUTHV4_KEY");
    let key2 = getenv("AUTHV4_KEY2");
    let hwid = getenv("AUTHV4_HWID");

    let mut app = Client::new(&pid, &base, None, None);
    app.init().expect("init error");
    check("init", !app.server_key.clone().unwrap_or_default().is_empty());
    let licensed = app.license(&key, Some(&hwid)).expect("license error");
    check("license", licensed.remaining > 80000);
    check("heartbeat", app.heartbeat().expect("heartbeat error") > 80000);
    let info = app.info().expect("info error");
    check("info", info["status"] == "active");
    check(
        "variable",
        app.variable("offset").expect("variable error") == "0x10",
    );
    let vars = app.variables().expect("variables error");
    check("variables", vars.get("offset").map(String::as_str) == Some("0x10"));
    check(
        "file",
        app.file("app.bin").expect("file error") == b"sdk-file-secret-bytes",
    );
    let hooked = app.webhook("orders", "ping").expect("webhook error");
    check("webhook", hooked["status"] == 200);
    let data = serde_json::json!({"offset": "0x20", "label": "rust"});
    let added = app
        .table("config", "add_row", None, Some(data), 100)
        .expect("table add error");
    check("table add", added["ok"] == true);
    let rows = app
        .table("config", "get_rows", None, None, 100)
        .expect("table rows error");
    let found = rows["rows"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .any(|row| row["data"]["label"] == "rust")
        })
        .unwrap_or(false);
    check("table rows", found);

    let mut user = Client::new(&pid, &base, None, None);
    let uname = user
        .user_register("rustuser", "DemoPass123!", &key, None)
        .expect("user register error");
    check("user register", uname == "rustuser");
    let ulogged = user
        .user_login("rustuser", "DemoPass123!", Some(&hwid))
        .expect("user login error");
    check("user login", ulogged.remaining > 80000);
    let sub = user
        .user_upgrade("rustuser", &key2)
        .expect("user upgrade error");
    check("user upgrade", sub.active && sub.remaining > 80000);
    check(
        "user heartbeat",
        user.heartbeat().expect("user heartbeat error") > 80000,
    );
    check(
        "user variable",
        user.variable("offset").expect("user variable error") == "0x10",
    );

    let mut bad = Client::new(&pid, &base, None, None);
    match bad.license("ZZZZ-9999-ZZZZ-9999", Some(&hwid)) {
        Ok(_) => check("bad key rejected", false),
        Err(e) => check("bad key rejected", format!("{e}").contains("Invalid key")),
    }
    println!("RUST CHECKS PASSED");
}
