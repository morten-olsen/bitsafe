use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod approval;
mod config;
mod peer;
mod prompt;
mod server;
mod session;
mod ssh_agent;
mod state;
mod sync_worker;

#[tokio::main]
async fn main() -> Result<()> {
    // Check --allow-insecure-memory before anything else.
    let allow_insecure = std::env::args().any(|a| a == "--allow-insecure-memory");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    harden_memory(allow_insecure)?;

    let config = grimoire_common::config::load_config();
    tracing::info!(
        server_url = %config.server.url,
        auto_lock = grimoire_common::config::AUTO_LOCK_SECONDS,
        sync_interval = grimoire_common::config::SYNC_INTERVAL_SECONDS,
        approval_timeout = grimoire_common::config::APPROVAL_SECONDS,
        "Starting grimoire-service"
    );

    server::run(config).await
}

/// Apply memory hardening to protect secrets from swap and core dumps.
///
/// On Linux: `mlockall` prevents swapping, `PR_SET_DUMPABLE(0)` prevents core dumps.
/// On macOS: `PT_DENY_ATTACH` prevents debugger attachment.
///
/// Failure is fatal by default — a password manager must not run with degraded memory
/// protection unless the user explicitly opts in via `--allow-insecure-memory`.
fn harden_memory(allow_insecure: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: mlockall takes only flag constants — no pointers, no preconditions.
        // prctl with PR_SET_DUMPABLE takes a single integer argument. Both are
        // process-level operations with no memory safety implications.
        unsafe {
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
                if allow_insecure {
                    tracing::warn!(
                        "mlockall failed — running with --allow-insecure-memory, \
                         sensitive data may be swapped to disk"
                    );
                } else {
                    anyhow::bail!(
                        "mlockall failed — refusing to start without memory protection. \
                         Increase RLIMIT_MEMLOCK or pass --allow-insecure-memory to override."
                    );
                }
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                tracing::warn!("prctl(PR_SET_DUMPABLE, 0) failed — core dumps may be possible");
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // SAFETY: ptrace with PT_DENY_ATTACH takes no pointer arguments.
        // It prevents debuggers from attaching to this process — same mechanism
        // used by Apple's security daemon.
        unsafe {
            // PT_DENY_ATTACH = 31
            if libc::ptrace(31, 0, std::ptr::null_mut::<libc::c_char>(), 0) != 0 {
                tracing::warn!("ptrace(PT_DENY_ATTACH) failed — debugger attachment possible");
            }
        }
    }

    tracing::info!(
        allow_insecure,
        platform = std::env::consts::OS,
        "Memory hardening applied"
    );
    Ok(())
}
