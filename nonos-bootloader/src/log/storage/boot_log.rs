// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use super::ring::{LogRingBuffer, DEFAULT_RING_CAPACITY};
use crate::log::global::get_boot_tick;
use crate::log::types::{CompactLogEntry, LogEntry, LogLevel};

/// Boot log capacity
pub const BOOT_LOG_CAPACITY: usize = DEFAULT_RING_CAPACITY;

/// Global boot log storage
static BOOT_LOG: Mutex<LogRingBuffer<BOOT_LOG_CAPACITY>> = Mutex::new(LogRingBuffer::new());

/// Boot log enabled flag
static BOOT_LOG_ENABLED: AtomicBool = AtomicBool::new(true);

/// Critical error count
static CRITICAL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Error count
static ERROR_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Warning count
static WARN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Enable boot log storage
pub fn enable_boot_log() {
    BOOT_LOG_ENABLED.store(true, Ordering::Release);
}

/// Disable boot log storage
pub fn disable_boot_log() {
    BOOT_LOG_ENABLED.store(false, Ordering::Release);
}

/// Check if boot log is enabled
pub fn is_boot_log_enabled() -> bool {
    BOOT_LOG_ENABLED.load(Ordering::Acquire)
}

/// Store a log entry in boot log
pub fn store_boot_log(entry: &LogEntry) {
    if !is_boot_log_enabled() {
        return;
    }

    // Update counters
    match entry.level {
        LogLevel::Critical | LogLevel::Fatal => {
            CRITICAL_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        LogLevel::Error => {
            ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        LogLevel::Warn => {
            WARN_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }

    if let Some(mut log) = BOOT_LOG.try_lock() {
        log.push(entry);
    }
}

/// Store a simple message in boot log
pub fn store_boot_message(level: LogLevel, category: &str, message: &str) {
    if !is_boot_log_enabled() {
        return;
    }

    let tick = get_boot_tick();
    let entry = LogEntry::create(level, tick, category, message);
    store_boot_log(&entry);
}

/// Get boot log entry count
pub fn boot_log_count() -> usize {
    BOOT_LOG.lock().len()
}

/// Get boot log overflow count
pub fn boot_log_overflow() -> u64 {
    BOOT_LOG.lock().overflow_count()
}

/// Get critical error count
pub fn critical_count() -> usize {
    CRITICAL_COUNT.load(Ordering::Relaxed)
}

/// Get error count
pub fn error_count() -> usize {
    ERROR_COUNT.load(Ordering::Relaxed)
}

/// Get warning count
pub fn warn_count() -> usize {
    WARN_COUNT.load(Ordering::Relaxed)
}

/// Check if any critical errors occurred
pub fn has_critical_errors() -> bool {
    critical_count() > 0
}

/// Check if any errors occurred
pub fn has_errors() -> bool {
    error_count() > 0 || critical_count() > 0
}

/// Get last N entries from boot log
pub fn get_last_entries(count: usize) -> heapless::Vec<CompactLogEntry, 32> {
    let mut result = heapless::Vec::new();
    let log = BOOT_LOG.lock();
    let total = log.len();
    let start = total.saturating_sub(count);

    for i in start..total {
        if let Some(entry) = log.get(i) {
            let _ = result.push(*entry);
        }
    }

    result
}

/// Get entries by level from boot log
pub fn get_entries_by_level(level: LogLevel) -> heapless::Vec<CompactLogEntry, 32> {
    let mut result = heapless::Vec::new();
    let log = BOOT_LOG.lock();

    for entry in log.iter() {
        if entry.log_level() == level {
            if result.push(*entry).is_err() {
                break;
            }
        }
    }

    result
}

/// Clear boot log
pub fn clear_boot_log() {
    BOOT_LOG.lock().clear();
    CRITICAL_COUNT.store(0, Ordering::Relaxed);
    ERROR_COUNT.store(0, Ordering::Relaxed);
    WARN_COUNT.store(0, Ordering::Relaxed);
}

/// Boot log summary statistics
#[derive(Debug, Clone, Copy)]
pub struct BootLogStats {
    pub total_entries: usize,
    pub overflow_count: u64,
    pub critical_count: usize,
    pub error_count: usize,
    pub warn_count: usize,
}

/// Get boot log statistics
pub fn get_boot_log_stats() -> BootLogStats {
    let log = BOOT_LOG.lock();
    BootLogStats {
        total_entries: log.len(),
        overflow_count: log.overflow_count(),
        critical_count: critical_count(),
        error_count: error_count(),
        warn_count: warn_count(),
    }
}
