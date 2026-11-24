//! Client side of the daemon's Unix-socket JSON-RPC (newline-delimited JSON).
//! Used by the GUI and the native-messaging host.
pub mod paths;

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Client {
    pub fn connect(sock: &Path) -> std::io::Result<Self> {
        let s = UnixStream::connect(sock)?;
        Ok(Self { reader: BufReader::new(s.try_clone()?), writer: s })
    }

    pub fn connect_default() -> std::io::Result<Self> {
        Self::connect(&paths::socket_path())
    }

    /// Calls `method`; returns the `ok` value or the daemon's error message.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let mut line = serde_json::to_string(&json!({ "method": method, "params": params })).unwrap();
        line.push('\n');
        self.writer.write_all(line.as_bytes()).map_err(|e| format!("daemon not reachable: {e}"))?;
        let mut resp = String::new();
        self.reader.read_line(&mut resp).map_err(|e| format!("daemon not reachable: {e}"))?;
        let v: Value = serde_json::from_str(&resp).map_err(|e| format!("bad daemon reply: {e}"))?;
        match v.get("error") {
            Some(e) => Err(e.as_str().unwrap_or("error").to_string()),
            None => Ok(v.get("ok").cloned().unwrap_or(Value::Null)),
        }
    }
}
