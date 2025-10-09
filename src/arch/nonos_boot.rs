//! NØNOS-Neutral Boot Interface
//!
//! Early boot initialization routines for the kernel.

use crate::log::logger::log_info;

/// Performs early boot initialization in a platform-neutral manner.
/// This should be the first initialization step before any subsystem is accessed.
pub fn init_early() {
    // Attempt to initialize the logger first to capture diagnostics from the earliest stage.
    if let Err(e) = crate::log::init_logger() {
        // If logger setup fails, fallback to a minimal panic or error handler.
        // This ensures that early boot failures are not silent.
        panic!("Logger initialization failed during early boot: {:?}", e);
    }

    log_info!("Early boot initialization completed.");
}
