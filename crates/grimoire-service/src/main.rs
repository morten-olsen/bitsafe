use anyhow::Result;
use tracing_subscriber::EnvFilter;

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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Memory hardening (Linux)
    #[cfg(target_os = "linux")]
    harden_memory();

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

#[cfg(target_os = "linux")]
fn harden_memory() {
    unsafe {
        // Prevent swapping of sensitive data
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            tracing::warn!("mlockall failed — sensitive data may be swapped to disk");
        }
        // Prevent core dumps
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            tracing::warn!("prctl(PR_SET_DUMPABLE, 0) failed");
        }
    }
}
