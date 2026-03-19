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

    let config = bitsafe_common::config::load_config();
    tracing::info!(
        server_url = %config.server.url,
        auto_lock = config.service.auto_lock_seconds,
        sync_interval = config.service.sync_interval_seconds,
        "Starting bitsafe-service"
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
