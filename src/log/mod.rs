//! NØNOS Logging Subsystem

pub mod nonos_logger;

// Re-export for backward compatibility  
pub use nonos_logger as simple_logger;

pub use nonos_logger::{
    Severity,
    init as init_logger,
    log, enter_panic_mode, log_critical
};


// Logging functions


pub fn debug(msg: &str) {
    log(Severity::Debug, msg);
}

pub fn log_err(msg: &str) {
    log(Severity::Err, msg);
}


// Security logging macro
#[macro_export]
macro_rules! security_log {
    ($($arg:tt)*) => {
        $crate::log::log(crate::log::Severity::Fatal, &alloc::format!($($arg)*));
    };
}

/// Debug logging macro
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::log::debug(&alloc::format!($($arg)*));
    };
}

/// Warning logging macro
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::log(crate::log::Severity::Warn, &alloc::format!($($arg)*));
    };
}

/// Error logging macro
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log::log(crate::log::Severity::Err, &alloc::format!($($arg)*));
    };
}

/// Warning logging function macro
#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => {
        $crate::log::log(crate::log::Severity::Warn, &alloc::format!($($arg)*));
    };
}


// Re-export the macros
pub use {security_log, log_debug, error, log_warning};
// Re-export macros from crate root that are exported by #[macro_export]
pub use crate::info;

// Make logger submodule that re-exports macros for compatibility
pub mod logger {
    pub use crate::{log_warn, log_err, log_dbg, log_fatal, log_info};
    pub use super::{log, error, log_warning, enter_panic_mode, log_critical}; // The logging function and macros
    
    // Re-export with alt names for compatibility
    pub use crate::log_err as log_error;
    pub use crate::info;
    pub use super::nonos_logger::try_get_logger;
    pub use super::init_logger as init;
    
    // Create log macro for compatibility
    #[macro_export]
    macro_rules! logger_log {
        ($msg:expr) => {
            $crate::log::log($crate::log::Severity::Info, $msg);
        };
    }
    pub use logger_log as log;
}
