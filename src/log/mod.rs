//! NØNOS Logging Subsystem

pub mod logger;

pub use logger::{
    debug, enter_panic_mode, info, init as init_logger, log, log_dbg, log_err, log_fatal, log_info,
    log_warn, log_warn_macro as log_warning, security_log, try_get_logger, LogLevel, Logger,
    Severity,
};

/// Error logging macro - REAL IMPLEMENTATION
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log::log_err!($($arg)*)
    };
}

/// Warning logging macro - REAL IMPLEMENTATION
#[macro_export]
macro_rules! warning {
    ($($arg:tt)*) => {
        $crate::log::log_warn!($($arg)*)
    };
}

/// Warn logging macro - REAL IMPLEMENTATION  
#[macro_export]
macro_rules! log_warn_macro {
    ($($arg:tt)*) => {
        $crate::log::log_warn!(alloc::format!($($arg)*))
    };
}

// Re-export the macros
pub use {error, warning};
