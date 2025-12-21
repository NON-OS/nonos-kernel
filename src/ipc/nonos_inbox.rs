// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
// 
//! Per-Module IPC Inbox System
//! # RAM-Only Design
//!
//! All inbox data is held in memory. No persistence layer exists.
//! On system reset, all inboxes and queued messages are lost.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

use super::nonos_channel::IpcMessage;

// ============================================================================
// Constants
// ============================================================================

/// Default inbox capacity (messages)
pub const DEFAULT_INBOX_CAPACITY: usize = 1024;

/// Minimum inbox capacity
pub const MIN_INBOX_CAPACITY: usize = 16;

/// Maximum inbox capacity
pub const MAX_INBOX_CAPACITY: usize = 65536;

/// Spin loop iterations for backoff
const SPIN_BACKOFF_ITERATIONS: usize = 256;

// ============================================================================
// Inbox Error
// ============================================================================

/// Inbox operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxError {
    /// Inbox not found for the specified module
    NotFound { module: String },
    /// Inbox is full, cannot enqueue
    Full { module: String, capacity: usize },
    /// Enqueue operation timed out
    Timeout { module: String, waited_ms: u64 },
    /// Invalid capacity value
    InvalidCapacity { value: usize, min: usize, max: usize },
    /// Module name is empty
    EmptyModuleName,
}

impl InboxError {
    /// Get a short description of the error
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "Inbox not found",
            Self::Full { .. } => "Inbox full",
            Self::Timeout { .. } => "Enqueue timeout",
            Self::InvalidCapacity { .. } => "Invalid capacity",
            Self::EmptyModuleName => "Empty module name",
        }
    }
}

impl core::fmt::Display for InboxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound { module } => {
                write!(f, "Inbox not found for module '{}'", module)
            }
            Self::Full { module, capacity } => {
                write!(f, "Inbox full for module '{}' (capacity: {})", module, capacity)
            }
            Self::Timeout { module, waited_ms } => {
                write!(f, "Enqueue timeout for module '{}' after {}ms", module, waited_ms)
            }
            Self::InvalidCapacity { value, min, max } => {
                write!(f, "Invalid capacity {}: must be between {} and {}", value, min, max)
            }
            Self::EmptyModuleName => write!(f, "Module name cannot be empty"),
        }
    }
}

// ============================================================================
// Inbox Statistics
// ============================================================================

/// Statistics for a single inbox
#[derive(Debug, Default)]
struct InboxStats {
    enqueued: AtomicU64,
    dequeued: AtomicU64,
    dropped_full: AtomicU64,
    timeouts: AtomicU64,
    peak_size: AtomicUsize,
}

impl InboxStats {
    const fn new() -> Self {
        Self {
            enqueued: AtomicU64::new(0),
            dequeued: AtomicU64::new(0),
            dropped_full: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            peak_size: AtomicUsize::new(0),
        }
    }

    fn record_enqueue(&self, current_size: usize) {
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        // Update peak if current size is higher
        let mut peak = self.peak_size.load(Ordering::Relaxed);
        while current_size > peak {
            match self.peak_size.compare_exchange_weak(
                peak,
                current_size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }

    fn record_dequeue(&self) {
        self.dequeued.fetch_add(1, Ordering::Relaxed);
    }

    fn record_dropped(&self) {
        self.dropped_full.fetch_add(1, Ordering::Relaxed);
    }

    fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot of inbox statistics
#[derive(Debug, Clone, Copy)]
pub struct InboxStatsSnapshot {
    /// Total messages enqueued
    pub enqueued: u64,
    /// Total messages dequeued
    pub dequeued: u64,
    /// Messages dropped due to full inbox
    pub dropped_full: u64,
    /// Enqueue timeouts
    pub timeouts: u64,
    /// Peak queue size observed
    pub peak_size: usize,
    /// Current queue size
    pub current_size: usize,
    /// Inbox capacity
    pub capacity: usize,
}

impl core::fmt::Display for InboxStatsSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Inbox[enq:{} deq:{} drop:{} timeout:{} size:{}/{} peak:{}]",
            self.enqueued,
            self.dequeued,
            self.dropped_full,
            self.timeouts,
            self.current_size,
            self.capacity,
            self.peak_size
        )
    }
}

// ============================================================================
// Inbox
// ============================================================================

/// Per-module message inbox with bounded capacity
pub struct Inbox {
    /// Message queue
    queue: Mutex<alloc::collections::VecDeque<IpcMessage>>,
    /// Maximum capacity
    capacity: usize,
    /// Statistics
    stats: InboxStats,
    /// Creation timestamp
    created_at_ms: u64,
}

impl Inbox {
    /// Create a new inbox with specified capacity
    fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(alloc::collections::VecDeque::with_capacity(capacity)),
            capacity,
            stats: InboxStats::new(),
            created_at_ms: crate::time::timestamp_millis(),
        }
    }

    /// Check if inbox is full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.queue.lock().len() >= self.capacity
    }

    /// Check if inbox is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    /// Get current queue length
    #[inline]
    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Get inbox capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get inbox age in milliseconds
    #[inline]
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.created_at_ms)
    }

    /// Enqueue a message with timeout
    ///
    /// Spins with backoff until space is available or timeout expires.
    fn enqueue_with_timeout(&self, msg: IpcMessage, timeout_ms: u64) -> Result<(), InboxError> {
        let start = crate::time::timestamp_millis();

        loop {
            {
                let mut q = self.queue.lock();
                if q.len() < self.capacity {
                    q.push_back(msg);
                    let size = q.len();
                    drop(q);
                    self.stats.record_enqueue(size);
                    return Ok(());
                }
            }

            let elapsed = crate::time::timestamp_millis().saturating_sub(start);
            if elapsed >= timeout_ms {
                self.stats.record_timeout();
                return Err(InboxError::Timeout {
                    module: String::new(), // Filled in by caller
                    waited_ms: elapsed,
                });
            }

            // Spin backoff
            for _ in 0..SPIN_BACKOFF_ITERATIONS {
                core::hint::spin_loop();
            }
        }
    }

    /// Try to enqueue without blocking
    fn try_enqueue(&self, msg: IpcMessage) -> Result<(), IpcMessage> {
        let mut q = self.queue.lock();
        if q.len() < self.capacity {
            q.push_back(msg);
            let size = q.len();
            drop(q);
            self.stats.record_enqueue(size);
            Ok(())
        } else {
            self.stats.record_dropped();
            Err(msg)
        }
    }

    /// Dequeue next message
    #[inline]
    fn dequeue(&self) -> Option<IpcMessage> {
        let msg = self.queue.lock().pop_front();
        if msg.is_some() {
            self.stats.record_dequeue();
        }
        msg
    }

    /// Peek at next message without removing
    fn peek(&self) -> Option<IpcMessage> {
        self.queue.lock().front().cloned()
    }

    /// Get statistics snapshot
    fn get_stats(&self) -> InboxStatsSnapshot {
        InboxStatsSnapshot {
            enqueued: self.stats.enqueued.load(Ordering::Relaxed),
            dequeued: self.stats.dequeued.load(Ordering::Relaxed),
            dropped_full: self.stats.dropped_full.load(Ordering::Relaxed),
            timeouts: self.stats.timeouts.load(Ordering::Relaxed),
            peak_size: self.stats.peak_size.load(Ordering::Relaxed),
            current_size: self.len(),
            capacity: self.capacity,
        }
    }

    /// Clear all messages from inbox
    fn clear(&self) -> usize {
        let mut q = self.queue.lock();
        let count = q.len();
        q.clear();
        count
    }
}

// ============================================================================
// Global Registry
// ============================================================================

/// Registry of all inboxes
struct Registry {
    map: BTreeMap<String, Arc<Inbox>>,
}

impl Registry {
    const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

/// Global inbox registry
static REGISTRY: RwLock<Registry> = RwLock::new(Registry::new());

/// Default capacity for new inboxes
static DEFAULT_CAP: AtomicUsize = AtomicUsize::new(DEFAULT_INBOX_CAPACITY);

/// Global statistics
static GLOBAL_STATS: GlobalStats = GlobalStats::new();

struct GlobalStats {
    total_inboxes_created: AtomicU64,
    total_inboxes_removed: AtomicU64,
}

impl GlobalStats {
    const fn new() -> Self {
        Self {
            total_inboxes_created: AtomicU64::new(0),
            total_inboxes_removed: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Set the default inbox capacity for future registrations
///
/// Capacity is clamped to valid range.
pub fn set_default_capacity(cap: usize) {
    let clamped = cap.clamp(MIN_INBOX_CAPACITY, MAX_INBOX_CAPACITY);
    DEFAULT_CAP.store(clamped, Ordering::Relaxed);
}

/// Get the current default inbox capacity
pub fn get_default_capacity() -> usize {
    DEFAULT_CAP.load(Ordering::Relaxed)
}

/// Register an inbox for a module
///
/// If inbox already exists, this is a no-op.
pub fn register_inbox(module: &str) {
    if module.is_empty() {
        return;
    }

    let cap = DEFAULT_CAP.load(Ordering::Relaxed);
    let mut reg = REGISTRY.write();

    if !reg.map.contains_key(module) {
        reg.map.insert(module.into(), Arc::new(Inbox::new(cap)));
        GLOBAL_STATS.total_inboxes_created.fetch_add(1, Ordering::Relaxed);
    }
}

/// Register an inbox with custom capacity
pub fn register_inbox_with_capacity(module: &str, capacity: usize) -> Result<(), InboxError> {
    if module.is_empty() {
        return Err(InboxError::EmptyModuleName);
    }

    if capacity < MIN_INBOX_CAPACITY || capacity > MAX_INBOX_CAPACITY {
        return Err(InboxError::InvalidCapacity {
            value: capacity,
            min: MIN_INBOX_CAPACITY,
            max: MAX_INBOX_CAPACITY,
        });
    }

    let mut reg = REGISTRY.write();

    if !reg.map.contains_key(module) {
        reg.map.insert(module.into(), Arc::new(Inbox::new(capacity)));
        GLOBAL_STATS.total_inboxes_created.fetch_add(1, Ordering::Relaxed);
    }

    Ok(())
}

/// Unregister an inbox and remove all queued messages
pub fn unregister_inbox(module: &str) -> Option<usize> {
    let mut reg = REGISTRY.write();
    if let Some(inbox) = reg.map.remove(module) {
        GLOBAL_STATS.total_inboxes_removed.fetch_add(1, Ordering::Relaxed);
        Some(inbox.len())
    } else {
        None
    }
}

/// Check if a module's inbox is full
pub fn is_full(module: &str) -> bool {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.is_full()).unwrap_or(false)
}

/// Check if a module's inbox is empty
pub fn is_empty(module: &str) -> bool {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.is_empty()).unwrap_or(true)
}

/// Enqueue a message with timeout
///
/// Auto-registers inbox if missing.
pub fn enqueue_with_timeout(
    module: &str,
    msg: IpcMessage,
    timeout_ms: u64,
) -> Result<(), &'static str> {
    register_inbox(module);

    let reg = REGISTRY.read();
    let inbox = reg.map.get(module).ok_or("inbox not found")?;

    inbox.enqueue_with_timeout(msg, timeout_ms).map_err(|e| match e {
        InboxError::Timeout { .. } => "inbox full (timeout)",
        _ => "enqueue failed",
    })
}

/// Try to enqueue without blocking
///
/// Returns the message back if inbox is full.
pub fn try_enqueue(module: &str, msg: IpcMessage) -> Result<(), IpcMessage> {
    register_inbox(module);

    let reg = REGISTRY.read();
    if let Some(inbox) = reg.map.get(module) {
        inbox.try_enqueue(msg)
    } else {
        Err(msg)
    }
}

/// Dequeue a message from module's inbox
///
/// Auto-registers inbox if missing.
pub fn dequeue(module: &str) -> Option<IpcMessage> {
    register_inbox(module);

    let reg = REGISTRY.read();
    reg.map.get(module).and_then(|i| i.dequeue())
}

/// Try to dequeue without auto-registration
pub fn try_dequeue(module: &str) -> Option<IpcMessage> {
    let reg = REGISTRY.read();
    reg.map.get(module).and_then(|inbox| inbox.dequeue())
}

/// Peek at next message without removing
pub fn peek(module: &str) -> Option<IpcMessage> {
    let reg = REGISTRY.read();
    reg.map.get(module).and_then(|i| i.peek())
}

/// Get current inbox length for a module
pub fn len(module: &str) -> usize {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.len()).unwrap_or(0)
}

/// Get inbox capacity for a module
pub fn capacity(module: &str) -> Option<usize> {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.capacity())
}

/// Check if an inbox exists for a module
pub fn exists(module: &str) -> bool {
    let reg = REGISTRY.read();
    reg.map.contains_key(module)
}

/// Get statistics for a module's inbox
pub fn get_inbox_stats(module: &str) -> Option<InboxStatsSnapshot> {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.get_stats())
}

/// Clear all messages from a module's inbox
pub fn clear(module: &str) -> usize {
    let reg = REGISTRY.read();
    reg.map.get(module).map(|i| i.clear()).unwrap_or(0)
}

/// List all registered inbox names
pub fn list_inboxes() -> alloc::vec::Vec<String> {
    let reg = REGISTRY.read();
    reg.map.keys().cloned().collect()
}

/// Get total number of registered inboxes
pub fn inbox_count() -> usize {
    let reg = REGISTRY.read();
    reg.map.len()
}

/// Get global inbox system statistics
pub fn get_global_stats() -> (u64, u64) {
    (
        GLOBAL_STATS.total_inboxes_created.load(Ordering::Relaxed),
        GLOBAL_STATS.total_inboxes_removed.load(Ordering::Relaxed),
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbox_error_display() {
        let e = InboxError::NotFound {
            module: "test".into(),
        };
        assert!(format!("{}", e).contains("test"));

        let e = InboxError::Full {
            module: "mod1".into(),
            capacity: 100,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("mod1"));
        assert!(msg.contains("100"));

        let e = InboxError::Timeout {
            module: "mod2".into(),
            waited_ms: 500,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("mod2"));
        assert!(msg.contains("500"));

        let e = InboxError::InvalidCapacity {
            value: 5,
            min: 16,
            max: 65536,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("5"));
        assert!(msg.contains("16"));

        let e = InboxError::EmptyModuleName;
        assert!(format!("{}", e).contains("empty"));
    }

    #[test]
    fn test_inbox_stats_display() {
        let snap = InboxStatsSnapshot {
            enqueued: 100,
            dequeued: 90,
            dropped_full: 5,
            timeouts: 2,
            peak_size: 50,
            current_size: 10,
            capacity: 1024,
        };
        let s = format!("{}", snap);
        assert!(s.contains("100"));
        assert!(s.contains("90"));
        assert!(s.contains("10/1024"));
    }

    #[test]
    fn test_capacity_clamping() {
        // Test min clamping
        set_default_capacity(1);
        assert_eq!(get_default_capacity(), MIN_INBOX_CAPACITY);

        // Test max clamping
        set_default_capacity(1_000_000);
        assert_eq!(get_default_capacity(), MAX_INBOX_CAPACITY);

        // Test normal value
        set_default_capacity(512);
        assert_eq!(get_default_capacity(), 512);

        // Reset to default
        set_default_capacity(DEFAULT_INBOX_CAPACITY);
    }

    #[test]
    fn test_inbox_creation() {
        let inbox = Inbox::new(100);
        assert!(inbox.is_empty());
        assert!(!inbox.is_full());
        assert_eq!(inbox.len(), 0);
        assert_eq!(inbox.capacity(), 100);
    }

    #[test]
    fn test_register_with_invalid_capacity() {
        let result = register_inbox_with_capacity("test_mod", 5);
        assert!(matches!(result, Err(InboxError::InvalidCapacity { .. })));

        let result = register_inbox_with_capacity("", 100);
        assert!(matches!(result, Err(InboxError::EmptyModuleName)));
    }
}
