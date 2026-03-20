use crate::state::{SharedState, VaultState};
use bitsafe_common::config::{AUTO_LOCK_SECONDS, SYNC_INTERVAL_SECONDS};
use std::time::Duration;
use tokio::time;

/// Periodically checks if the vault should be auto-locked due to inactivity.
pub async fn auto_lock_worker(state: SharedState) {
    let check_interval = Duration::from_secs(30);
    let timeout = Duration::from_secs(AUTO_LOCK_SECONDS);

    loop {
        time::sleep(check_interval).await;

        let should_lock = {
            let s = state.read().await;
            s.vault_state == VaultState::Unlocked && s.last_activity.elapsed() >= timeout
        };

        if should_lock {
            let mut s = state.write().await;
            // Re-check after acquiring write lock (TOCTOU double-check)
            if s.vault_state == VaultState::Unlocked && s.last_activity.elapsed() >= timeout {
                tracing::info!("Auto-locking vault due to inactivity");
                if let Err(e) = s.lock().await {
                    tracing::error!("Failed to auto-lock: {e}");
                }
            }
        }
    }
}

/// Periodically syncs the vault while unlocked.
pub async fn background_sync_worker(state: SharedState) {
    let interval = Duration::from_secs(SYNC_INTERVAL_SECONDS);

    loop {
        time::sleep(interval).await;

        let sync_result = {
            let s = state.read().await;
            if s.vault_state != VaultState::Unlocked {
                continue;
            }
            let (Some(sdk), Some(server_url)) = (&s.sdk, &s.server_url) else {
                continue;
            };
            sdk.sync().sync(server_url).await
        };

        match sync_result {
            Ok(()) => {
                let mut s = state.write().await;
                s.last_sync = Some(chrono::Utc::now());
                tracing::debug!("Background sync completed");
            }
            Err(e) => {
                tracing::warn!("Background sync failed: {e}");
            }
        }
    }
}

/// Run an immediate sync. Called after unlock.
pub async fn sync_now(state: &SharedState) {
    let sync_result = {
        let s = state.read().await;
        let (Some(sdk), Some(server_url)) = (&s.sdk, &s.server_url) else {
            tracing::warn!("Cannot sync: not logged in");
            return;
        };
        sdk.sync().sync(server_url).await
    };

    match sync_result {
        Ok(()) => {
            let mut s = state.write().await;
            s.last_sync = Some(chrono::Utc::now());
            tracing::info!("Sync completed");
        }
        Err(e) => {
            tracing::warn!("Sync after unlock failed: {e}");
        }
    }
}
