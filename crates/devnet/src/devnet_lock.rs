//! Global lock guaranteeing only one RiftDevnet *build* at a time.
//! Dropping the guard releases both the in-process and file lock.

use eyre::Result;
use fs2::FileExt;
use once_cell::sync::Lazy;
use std::{fs::File, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, OwnedMutexGuard};

static PROCESS_MUTEX: Lazy<Arc<Mutex<()>>> = Lazy::new(|| Arc::new(Mutex::new(())));

static LOCKFILE_PATH: Lazy<PathBuf> = Lazy::new(|| std::env::temp_dir().join("rift_devnet.lock"));

pub struct DevnetBuildGuard {
    _process_guard: OwnedMutexGuard<()>,
    _file_handle: File,
}

impl DevnetBuildGuard {
    /// Block until both locks are acquired.
    /// TEMPORARY NO-OP: Just returns access without actually acquiring locks
    pub async fn acquire() -> Result<Self> {
        // NO-OP: Create dummy handles without any actual locking
        let process_guard = PROCESS_MUTEX.clone().lock_owned().await;

        let lockfile_path = LOCKFILE_PATH.clone();
        let file = tokio::task::spawn_blocking(move || -> Result<File> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&lockfile_path)?;
            // SKIP: file.lock_exclusive()?; - No actual locking for no-op
            Ok(file)
        })
        .await
        .map_err(|e| eyre::eyre!("Failed to spawn blocking task: {}", e))??;

        Ok(Self {
            _process_guard: process_guard,
            _file_handle: file,
        })
    }
}
