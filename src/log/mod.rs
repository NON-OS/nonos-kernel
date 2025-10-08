//! NØNOS Logging Subsystem

pub mod nonos_logger;

// Re-export for backward compatibility
pub use nonos_logger as logger;

pub use nonos_logger::{
    Logger, LogLevel, Severity,
    init as init_logger,
    try_get_logger,
    log, log_info, log_warn, log_err, log_dbg, log_fatal,
    info, debug, security_log, log_warn_macro as log_warning,
    enter_panic_mode
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
