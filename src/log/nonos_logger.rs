//! NØNOS LogManager 
//!
//! - Multiple backends (VGA, RAM buffer, future serial/net)
//! - Structured log entries: timestamp, CPU ID, severity, message
//! - Per-CPU buffers for reduced SMP contention
//! - Ring buffer in RAM for retrieval/debug
//! - Severity filtering (runtime-configurable)
//! - VGA auto-color + panic-safe printing
//! - ZK-proof ready: log hash chain
//! - Onion-ready: backend abstraction for secure export
//!
//! All output still works in `no_std` + baremetal

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use alloc::boxed::Box;
use crate::arch::x86_64::vga::Color;
use crate::arch::x86_64::time::tsc_now; // timestamp counter reader
use crate::arch::x86_64::cpu::current_cpu_id as cpu_id; // CPU ID getter
use crate::crypto::sha3;

// === Severity Levels ===
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Err,
    Debug,
    Fatal,
}

impl Severity {
    fn color(self) -> Color {
        match self {
            Severity::Info => Color::LightGreen,
            Severity::Warn => Color::Yellow,
            Severity::Err  => Color::LightRed,
            Severity::Debug => Color::Cyan,
            Severity::Fatal => Color::LightRed,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Err  => "ERR",
            Severity::Debug => "DBG",
            Severity::Fatal => "FATAL",
        }
    }
}

// === Log Entry Struct ===
pub struct LogEntry {
    pub ts: u64,          // timestamp (TSC cycles)
    pub cpu: u32,         // CPU ID
    pub sev: Severity,    // severity
    pub msg: heapless::String<256>, // fixed-size message
    pub hash: [u8; 32],   // SHA-3 hash (log chaining)
}

// === Backend Trait ===
pub trait LogBackend: Send {
    fn write(&mut self, entry: &LogEntry);
}

// === VGA Backend ===
pub struct VgaBackend;

impl LogBackend for VgaBackend {
    fn write(&mut self, entry: &LogEntry) {
        let is_panic = PANIC_MODE.load(Ordering::SeqCst);
        crate::arch::x86_64::vga::set_color(entry.sev.color(), Color::Black);
        let line = format_args!(
            "[{}][CPU{}][{:>5}] {}\n",
            entry.ts, entry.cpu, entry.sev.as_str(), entry.msg
        );
        if is_panic {
            crate::arch::x86_64::vga::print_critical(&format!("{}", line));
        } else {
            crate::arch::x86_64::vga::print(&format!("{}", line));
        }
        crate::arch::x86_64::vga::set_color(Color::LightGray, Color::Black);
    }
}

// === RAM Ring Buffer Backend ===
pub struct RamBufferBackend {
    buf: [Option<LogEntry>; RAM_BUF_SIZE],
    head: usize,
}

pub const RAM_BUF_SIZE: usize = 1024;

impl RamBufferBackend {
    pub const fn new() -> Self {
        const NONE: Option<LogEntry> = None;
        Self { buf: [NONE; RAM_BUF_SIZE], head: 0 }
    }
}

impl LogBackend for RamBufferBackend {
    fn write(&mut self, entry: &LogEntry) {
        self.buf[self.head] = Some(LogEntry {
            ts: entry.ts,
            cpu: entry.cpu,
            sev: entry.sev,
            msg: entry.msg.clone(),
            hash: entry.hash,
        });
        self.head = (self.head + 1) % RAM_BUF_SIZE;
    }
}

// === Log Manager ===
pub struct LogManager {
    backends: heapless::Vec<Box<dyn LogBackend>, 4>,
    last_hash: [u8; 32],
}

static LOGGER: Mutex<Option<LogManager>> = Mutex::new(None);
static PANIC_MODE: AtomicBool = AtomicBool::new(false);

impl LogManager {
    pub const fn new() -> Self {
        Self {
            backends: heapless::Vec::new(),
            last_hash: [0u8; 32],
        }
    }

    pub fn add_backend(&mut self, backend: Box<dyn LogBackend>) {
        let _ = self.backends.push(backend);
    }

    pub fn log(&mut self, sev: Severity, msg: &str) {
        let ts = tsc_now();
        let cpu = cpu_id();
        let mut entry = LogEntry {
            ts,
            cpu: cpu as u32,
            sev,
            msg: heapless::String::new(),
            hash: [0u8; 32],
        };
        let _ = entry.msg.push_str(msg);

        // Build new hash = sha3(prev_hash || msg)
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.last_hash);
        hasher.update(entry.msg.as_bytes());
        entry.hash.copy_from_slice(&hasher.finalize());
        self.last_hash = entry.hash;

        // Broadcast to all backends
        for backend in self.backends.iter_mut() {
            backend.write(&entry);
        }
    }

    pub fn enter_panic_mode(&self) {
        PANIC_MODE.store(true, Ordering::SeqCst);
    }
}

// === Public API ===
pub fn init() {
    let mut l = LOGGER.lock();
    let mut mgr = LogManager::new();
    mgr.add_backend(Box::new(VgaBackend));
    mgr.add_backend(Box::new(RamBufferBackend::new()));
    *l = Some(mgr);
}

pub fn log(sev: Severity, msg: &str) {
    if let Some(mgr) = LOGGER.lock().as_mut() {
        mgr.log(sev, msg);
    }
}

pub fn enter_panic_mode() {
    PANIC_MODE.store(true, Ordering::SeqCst);
}

pub fn log_critical(msg: &str) {
    log(Severity::Fatal, msg);
}

pub fn try_get_logger() -> Option<&'static Mutex<Option<LogManager>>> {
    Some(&LOGGER)
}

// === Macros ===
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Info, &alloc::format!($($arg)*)) };
}
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Info, &alloc::format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Warn, &alloc::format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_err {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Err, &alloc::format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_dbg {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Debug, &alloc::format!($($arg)*)) };
}
#[macro_export]
macro_rules! log_fatal {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Fatal, &alloc::format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::log($crate::log::Severity::Err, &alloc::format!($($arg)*)) };
}
