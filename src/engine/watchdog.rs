use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

pub struct Watchdog {
    is_cancelled: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Spawn a safety watchdog timer.
    /// If `cancel()` is not called within `timeout`, `on_timeout` is executed!
    pub fn start<F>(timeout: Duration, on_timeout: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let is_cancelled = Arc::new(AtomicBool::new(false));
        let cancel_flag = is_cancelled.clone();

        info!("Watchdog timer started: {} seconds", timeout.as_secs());
        let handle = tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if !cancel_flag.load(Ordering::SeqCst) {
                error!("WATCHDOG EXPIRED! Health check or confirmation timed out. Triggering automatic rollback!");
                on_timeout();
            } else {
                info!("Watchdog gracefully disarmed.");
            }
        });

        Self {
            is_cancelled,
            handle: Some(handle),
        }
    }

    /// Cancel/disarm the watchdog (called when test passes and commit succeeds)
    pub fn cancel(&mut self) {
        self.is_cancelled.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if !self.is_cancelled.load(Ordering::SeqCst) {
            warn!("Watchdog dropped without explicit cancellation! Aborting background timer to prevent ghost rollback.");
            if let Some(h) = self.handle.take() {
                h.abort();
            }
        }
    }
}
