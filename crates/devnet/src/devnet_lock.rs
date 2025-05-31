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
    pub async fn acquire() -> Result<Self> {
        // 1  Tokio mutex for in-process serialisation
        let process_guard = PROCESS_MUTEX.clone().lock_owned().await;

        // 2  File lock for cross-process serialisation (async-safe)
        let lockfile_path = LOCKFILE_PATH.clone();
        let file = tokio::task::spawn_blocking(move || -> Result<File> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&lockfile_path)?;
            file.lock_exclusive()?; // Now safe - runs on blocking thread pool
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
