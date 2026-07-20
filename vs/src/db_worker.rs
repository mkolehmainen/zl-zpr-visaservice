//! Background worker for keeping the visa service database lock alive.
//!
//! The service uses a shared database-backed lock to make sure only one visa
//! service instance is active at a time. This worker renews that lock while the
//! process runs and terminates the process if the lock is lost or too close to
//! expiry, preventing split-brain behavior where two instances might issue or
//! mutate visas concurrently.

use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, trace, warn};

use crate::config;
use crate::db::{DbConnection, LockDescriptor};

/// Renew the DB instance lock on a timer, shutting the process down if the lock
/// is lost or renewal is failing so long that expiry is imminent. Takes the db
/// handle directly (not the full Assembly) so it can be spawned immediately
/// after lock acquisition, before the rest of startup.
pub async fn launch(db: Arc<dyn DbConnection>, vslock: LockDescriptor) {
    let mut last_renewed = Instant::now();
    let mut delay = config::VALKEY_LOCK_REFRESH_SECS;
    loop {
        tokio::time::sleep(delay).await;
        match db.acquire_or_renew_lock(&vslock).await {
            Ok(true) => {
                last_renewed = Instant::now();
                delay = config::VALKEY_LOCK_REFRESH_SECS;
                trace!("vs db lock renewed");
            }
            Ok(false) => {
                error!("vs db lock lost, shutting down");
                // TODO: signal shutdown to main loop instead of just panicing?
                error!("vs db lock lost");
                process::exit(1);
            }
            Err(e) => {
                let age = last_renewed.elapsed();
                // If the next retry attempt could arrive after the lock has already
                // expired, shut down now rather than risk another instance taking
                // the lock while we are still running.
                if age + config::VALKEY_LOCK_RETRY_SECS
                    >= config::VALKEY_LOCK_TIMEOUT + Duration::from_secs(1)
                {
                    error!(
                        "vs db lock renewal failing for {:?}, lock expiry imminent, shutting down: {:?}",
                        age, e
                    );
                    error!("vs db lock expiry imminent");
                    process::exit(1);
                }
                warn!(
                    "failed to renew vs db lock (last renewed {:?} ago), retrying in {:?}: {:?}",
                    age,
                    config::VALKEY_LOCK_RETRY_SECS,
                    e
                );
                delay = config::VALKEY_LOCK_RETRY_SECS;
            }
        }
    }
}
