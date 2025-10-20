//! NØNOS Logging Subsystem

pub mod nonos_logger;

// Re-export for backward compatibility
pub use nonos_logger as logger;

pub use nonos_logger::{
    Severity,
    init as init_logger,
    log, enter_panic_mode, log_critical
};

// Logging functions
pub fn info(msg: &str) {
    log(Severity::Info, msg);
}

pub fn warn(msg: &str) {
    log(Severity::Warn, msg);  
}

pub fn debug(msg: &str) {
    log(Severity::Debug, msg);
}

pub fn security_log(msg: &str) {
    log(Severity::Fatal, msg);
}

pub fn log_warning(msg: &str) {
    log(Severity::Warn, msg);
}

/// Error logging macro 
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log::log_err!($($arg)*)
    };
}

/// Warning logging macro 
#[macro_export]
macro_rules! warning {
    ($($arg:tt)*) => {
        $crate::log::log_warn!($($arg)*)
    };
}

/// Warn logging macro   
#[macro_export]
macro_rules! log_warn_macro {
    ($($arg:tt)*) => {
        $crate::log::log_warn!(alloc::format!($($arg)*))
    };
}

// Re-export the macros
pub use {error, warning};
