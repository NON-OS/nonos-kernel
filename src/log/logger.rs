//! NØNOS Cryptographic Logger
//!
//! Chain-hashed audit logger with VGA/serial/network sinks.
//! All log entries are cryptographically linked for tamper evidence.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::arch::x86_64::{serial, vga};
use crate::crypto::hash::blake3_hash;
use alloc::vec::Vec;

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4,
}

pub type LogLevel = Severity;

/// Log entry with cryptographic chaining
#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub severity: Severity,
    pub message: heapless::String<256>,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
}

/// Ring buffer for log entries
const LOG_BUFFER_SIZE: usize = 1024;

pub struct Logger {
    entries: Mutex<heapless::Deque<LogEntry, LOG_BUFFER_SIZE>>,
    prev_hash: Mutex<[u8; 32]>,
    sequence: AtomicU64,
    panic_mode: AtomicBool,
    min_level: Mutex<Severity>,
}

static LOGGER: Logger = Logger {
    entries: Mutex::new(heapless::Deque::new()),
    prev_hash: Mutex::new([0; 32]),
    sequence: AtomicU64::new(0),
    panic_mode: AtomicBool::new(false),
    min_level: Mutex::new(Severity::Debug),
};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the logging subsystem
pub fn init() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Set initial hash to boot entropy
    let boot_hash = blake3_hash(&crate::crypto::entropy::rand_u64().to_le_bytes());
    *LOGGER.prev_hash.lock() = boot_hash;

    log_info!("[LOG] Cryptographic logger initialized");
}

/// Get logger if initialized
pub fn try_get_logger() -> Option<&'static Logger> {
    if INITIALIZED.load(Ordering::Relaxed) {
        Some(&LOGGER)
    } else {
        None
    }
}

impl Logger {
    /// Main logging function
    pub fn log(&self, msg: &str) {
        self.log_with_severity(Severity::Info, msg);
    }

    pub fn log_with_severity(&self, severity: Severity, msg: &str) {
        // Check minimum level
        if severity < *self.min_level.lock() {
            return;
        }

        // Get timestamp
        let timestamp = unsafe {
            if let Some(timer) = crate::arch::x86_64::time::timer::now_ns_checked() {
                timer
            } else {
                self.sequence.fetch_add(1, Ordering::SeqCst)
            }
        };

        // Create message
        let mut message = heapless::String::new();
        let _ = message.push_str(msg);

        // Compute chained hash
        let prev_hash = *self.prev_hash.lock();
        let mut data = Vec::new();
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.push(severity as u8);
        data.extend_from_slice(message.as_bytes());
        data.extend_from_slice(&prev_hash);
        let hash = blake3_hash(&data);

        // Create entry
        let entry = LogEntry { timestamp, severity, message: message.clone(), hash, prev_hash };

        // Store in ring buffer
        {
            let mut entries = self.entries.lock();
            if entries.is_full() {
                let _ = entries.pop_front(); // Drop oldest
            }
            let _ = entries.push_back(entry.clone());
        }

        // Update chain
        *self.prev_hash.lock() = hash;

        // Output to sinks
        self.output_to_sinks(severity, &message);
    }

    fn output_to_sinks(&self, severity: Severity, msg: &str) {
        // Format with color codes for VGA
        let (fg, bg) = match severity {
            Severity::Debug => (vga::Color::Cyan, vga::Color::Black),
            Severity::Info => (vga::Color::LightGreen, vga::Color::Black),
            Severity::Warn => (vga::Color::Yellow, vga::Color::Black),
            Severity::Error => (vga::Color::LightRed, vga::Color::Black),
            Severity::Fatal => (vga::Color::White, vga::Color::Red),
        };

        // VGA output
        if self.panic_mode.load(Ordering::Relaxed) {
            vga::print_critical(msg);
            vga::print_critical("\n");
        } else {
            vga::set_color(fg, bg);
            vga::print(msg);
            vga::print("\n");
            vga::set_color(vga::Color::LightGray, vga::Color::Black);
        }

        // Serial output
        if let Some(mut serial) = unsafe { serial::get_serial() } {
            let _ = writeln!(serial, "[{:?}] {}", severity, msg);
        }

        // Network sink (if connected)
        #[cfg(feature = "net-log")]
        if crate::net::is_connected() {
            crate::net::send_log(severity, msg);
        }
    }

    /// Enter panic mode (bypass locks for critical output)
    pub fn enter_panic_mode(&self) {
        self.panic_mode.store(true, Ordering::SeqCst);
    }

    /// Get current log chain hash
    pub fn get_chain_hash(&self) -> [u8; 32] {
        *self.prev_hash.lock()
    }

    /// Export recent entries for attestation
    pub fn export_recent(&self, count: usize) -> Vec<LogEntry> {
        let entries = self.entries.lock();
        let mut result = Vec::new();

        let start = if entries.len() > count { entries.len() - count } else { 0 };

        for (i, entry) in entries.iter().enumerate() {
            if i >= start {
                result.push(entry.clone());
            }
        }

        result
    }

    /// Verify log chain integrity
    pub fn verify_chain(&self) -> bool {
        let entries = self.entries.lock();
        let mut prev = [0u8; 32];

        for entry in entries.iter() {
            // Recompute hash
            let mut data = Vec::new();
            data.extend_from_slice(&entry.timestamp.to_le_bytes());
            data.push(entry.severity as u8);
            data.extend_from_slice(entry.message.as_bytes());
            data.extend_from_slice(&entry.prev_hash);
            let computed = blake3_hash(&data);

            if computed != entry.hash {
                return false;
            }

            if prev != [0; 32] && prev != entry.prev_hash {
                return false;
            }

            prev = entry.hash;
        }

        true
    }
}

// ===== Convenience Macros =====

#[macro_export]
macro_rules! log {
    ($msg:expr) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            logger.log($msg);
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Info, &msg);
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Warn, &msg);
        }
    };
}

#[macro_export]
macro_rules! log_err {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Error, &msg);
        }
    };
}

#[macro_export]
macro_rules! log_dbg {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Debug, &msg);
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Debug, &msg);
        }
    };
}

#[macro_export]
macro_rules! log_fatal {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Fatal, &msg);
        }
    };
}

// Additional convenience macros for advanced features
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Info, &msg);
        }
    };
}

#[macro_export]
macro_rules! warn_log {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Warn, &msg);
        }
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!($($arg)*);
            logger.log_with_severity($crate::log::Severity::Debug, &msg);
        }
    };
}

#[macro_export]
macro_rules! security_log {
    ($($arg:tt)*) => {
        if let Some(logger) = $crate::log::try_get_logger() {
            let msg = $crate::format!("[SECURITY] {}", $crate::format!($($arg)*));
            logger.log_with_severity($crate::log::Severity::Warn, &msg);
        }
    };
}

pub use {
    debug, info, log, log_dbg, log_debug, log_err, log_fatal, log_info, log_warn, security_log,
};

// Re-export warn_log with different name to avoid conflict with builtin
// attribute
pub use warn_log as log_warn_macro;

/// Helper to enter panic mode
pub fn enter_panic_mode() {
    if let Some(logger) = try_get_logger() {
        logger.enter_panic_mode();
    }
}

/// Log critical system error
pub fn log_emergency(msg: &str) {
    if let Some(logger) = try_get_logger() {
        logger.log_with_severity(Severity::Fatal, msg);
    }
}

pub fn log_critical(msg: &str) {
    if let Some(logger) = try_get_logger() {
        logger.log_with_severity(Severity::Fatal, msg);
    }
}
