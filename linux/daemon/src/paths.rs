use std::path::PathBuf;

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(fallback))
}

/// `$XDG_DATA_HOME/peerpass`
pub fn data_dir() -> PathBuf {
    env_dir("XDG_DATA_HOME", ".local/share").join("peerpass")
}

/// `$XDG_RUNTIME_DIR/peerpass.sock` (or `$PEERPASS_SOCKET`).
pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("PEERPASS_SOCKET") {
        return PathBuf::from(p);
    }
    let rt = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
    rt.join("peerpass.sock")
}
