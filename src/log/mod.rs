//! Logging facilities

pub mod logger;

// Logging macros
macro_rules! info {
    ($($arg:tt)*) => {
        // Stub implementation
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        // Stub implementation
    };
}

macro_rules! security_log {
    ($($arg:tt)*) => {
        // Stub implementation
    };
}

macro_rules! log_warning {
    ($($arg:tt)*) => {
        // Stub implementation
    };
}

pub(crate) use info;
pub(crate) use debug;
pub(crate) use security_log;
pub(crate) use log_warning;

