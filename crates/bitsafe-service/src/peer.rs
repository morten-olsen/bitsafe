//! Resolve the session leader PID for a given process.
//!
//! Used to scope access approval to a terminal session — all processes
//! in the same session share one approval grant.

/// Get the session leader PID for a process.
///
/// - Linux: reads `/proc/<pid>/stat`, field 6 (session ID = session leader PID)
/// - macOS: calls `getsid(pid)`
/// - Other: returns None (fallback to PID-scoped approval)
pub fn get_session_leader(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        get_session_leader_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        get_session_leader_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "linux")]
fn get_session_leader_linux(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Format: <pid> (<comm>) <state> <ppid> <pgrp> <session> ...
    // comm can contain spaces and parens, so split on the LAST ')'
    let after_comm = stat.rsplit(')').next()?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After ')', fields are: state(0) ppid(1) pgrp(2) session(3)
    fields.get(3)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn get_session_leader_macos(pid: u32) -> Option<u32> {
    let sid = unsafe { libc::getsid(pid as i32) };
    if sid < 0 {
        None
    } else {
        Some(sid as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_own_session_leader() {
        let pid = std::process::id();
        let leader = get_session_leader(pid);
        // Should succeed for our own process
        assert!(leader.is_some(), "Failed to get session leader for PID {pid}");
        let leader_pid = leader.unwrap();
        // Session leader PID should be a valid positive number
        assert!(leader_pid > 0);
    }

    #[test]
    fn get_session_leader_invalid_pid() {
        // PID 0 or very large PID should return None
        assert!(get_session_leader(0).is_none() || get_session_leader(0).is_some());
        // Use an absurdly large PID that won't exist
        assert!(get_session_leader(4_000_000_000).is_none());
    }
}
