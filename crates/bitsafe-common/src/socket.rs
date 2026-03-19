use std::path::PathBuf;

/// Returns the directory for BitSafe runtime files.
///
/// Uses `$XDG_RUNTIME_DIR/bitsafe/` if available, otherwise falls back to
/// `/tmp/bitsafe-<uid>/` using the real user ID.
pub fn runtime_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("bitsafe")
    } else {
        // Use the real UID, not PID. This prevents symlink race attacks
        // where an attacker pre-creates /tmp/bitsafe-<predictable-pid>/.
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = std::process::id(); // non-Unix fallback (best effort)
        PathBuf::from(format!("/tmp/bitsafe-{uid}"))
    }
}

/// Returns the path to the main service socket.
pub fn service_socket_path() -> PathBuf {
    runtime_dir().join("bitsafe.sock")
}

/// Returns the path to the SSH agent socket.
pub fn ssh_agent_socket_path() -> PathBuf {
    runtime_dir().join("ssh-agent.sock")
}
