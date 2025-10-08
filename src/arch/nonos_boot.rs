//! NØNOS Architecture-Neutral Boot Interface
//!
//! Provides early boot initialization routines

use crate::log::logger::log_info;

/// Early boot initialization - architecture neutral
pub fn init_early() {
    log_info!("Early boot initialization starting");
    
    // Initialize critical subsystems first
    crate::log::init_logger();
    
    log_info!("Early boot initialization complete");
}