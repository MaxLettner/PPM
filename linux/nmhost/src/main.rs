//! Native-messaging host (stdin/stdout, u32 native-endian length + JSON).
//! Only a small allow-list of daemon calls is reachable from the browser.
use serde_json::{json, Value};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAX_MSG: usize = 1024 * 1024;

fn read_msg(r: &mut impl Read) -> Option<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = u32::from_ne_bytes(len) as usize;
    if n > MAX_MSG {
        return None;
    }
    let mut buf = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn write_msg(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let b = Zeroizing::new(serde_json::to_vec(v).unwrap());
    w.write_all(&(b.len() as u32).to_ne_bytes())?;
    w.write_all(&b)?;
    w.flush()
}

fn handle(req: &Value) -> Value {
    let method = req["method"].as_str().unwrap_or("");
    let params = match method {
        "status" => Value::Null,
        // Listing never includes passwords; they are fetched per click via "fill".
        "find" => json!({ "url": req["url"] }),
        "fill" | "totp" => json!({ "id": req["id"], "index": req["index"], "url": req["url"] }),
        _ => return json!({ "error": "method not allowed" }),
    };
    let mut c = match peerpassd::Client::connect_default() {
        Ok(c) => c,
        Err(_) => return json!({ "error": "peerpass is not running" }),
    };
    match c.call(method, params) {
        Ok(mut v) => {
            if method == "find" {
                for e in v.as_array_mut().into_iter().flatten() {
                    if let Some(o) = e.as_object_mut() {
                        o.remove("password");
                    }
                }
            }
            if method == "status" {
                v = json!({ "has_vault": v["has_vault"], "unlocked": v["unlocked"] });
            }
            json!({ "ok": v })
        }
        Err(e) => json!({ "error": e }),
    }
}

fn main() {
    let (mut stdin, mut stdout) = (std::io::stdin().lock(), std::io::stdout().lock());
    while let Some(req) = read_msg(&mut stdin) {
        if write_msg(&mut stdout, &handle(&req)).is_err() {
            return;
        }
    }
}
