use std::path::PathBuf;

/// Returns the directory for Grimoire runtime files.
///
/// Uses `$XDG_RUNTIME_DIR/grimoire/` if available, otherwise falls back to
/// `/tmp/grimoire-<uid>/` using the real user ID.
pub fn runtime_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("grimoire")
    } else {
        // Use the real UID, not PID. This prevents symlink race attacks
        // where an attacker pre-creates /tmp/grimoire-<predictable-pid>/.
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = std::process::id(); // non-Unix fallback (best effort)
        PathBuf::from(format!("/tmp/grimoire-{uid}"))
    }
}

/// Returns the path to the main service socket.
pub fn service_socket_path() -> PathBuf {
    runtime_dir().join("grimoire.sock")
}

/// Returns the path to the SSH agent socket.
pub fn ssh_agent_socket_path() -> PathBuf {
    runtime_dir().join("ssh-agent.sock")
}
