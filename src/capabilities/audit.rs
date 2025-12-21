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
//! Capability Audit Log

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::{Capability, CapabilityToken};

// ============================================================================
// Constants
// ============================================================================

/// Maximum audit log entries (ring buffer size)
const MAX_LOG_ENTRIES: usize = 4096;

// ============================================================================
// Audit Entry
// ============================================================================

/// Single audit log entry recording a capability use
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Timestamp when action occurred (ms since boot)
    pub timestamp_ms: u64,
    /// Module ID that owns the token
    pub owner_module: u64,
    /// Action being performed (static string for efficiency)
    pub action: &'static str,
    /// Specific capability used (if applicable)
    pub capability: Option<Capability>,
    /// Token nonce for correlation
    pub nonce: u64,
    /// Whether the action succeeded
    pub success: bool,
}

impl AuditEntry {
    /// Check if entry is within a time range
    #[inline]
    pub fn in_time_range(&self, start_ms: u64, end_ms: u64) -> bool {
        self.timestamp_ms >= start_ms && self.timestamp_ms <= end_ms
    }

    /// Check if entry matches a module ID
    #[inline]
    pub fn matches_module(&self, module_id: u64) -> bool {
        self.owner_module == module_id
    }

    /// Check if entry matches an action
    #[inline]
    pub fn matches_action(&self, action: &str) -> bool {
        self.action == action
    }

    /// Get entry age in milliseconds
    #[inline]
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.timestamp_ms)
    }
}

impl core::fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let cap_str = match &self.capability {
            Some(c) => alloc::format!("{:?}", c),
            None => alloc::string::String::from("-"),
        };
        let status = if self.success { "OK" } else { "FAIL" };
        write!(
            f,
            "[{}ms] mod:{} {} cap:{} nonce:{:016x} {}",
            self.timestamp_ms, self.owner_module, self.action, cap_str, self.nonce, status
        )
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Audit log statistics
struct AuditStats {
    /// Total entries logged (may exceed buffer size)
    total_logged: AtomicU64,
    /// Total successful actions
    success_count: AtomicU64,
    /// Total failed actions
    failure_count: AtomicU64,
}

impl AuditStats {
    const fn new() -> Self {
        Self {
            total_logged: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
        }
    }

    fn record(&self, success: bool) {
        self.total_logged.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failure_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Statistics snapshot
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditStatsSnapshot {
    /// Total entries ever logged
    pub total_logged: u64,
    /// Successful actions
    pub success_count: u64,
    /// Failed actions
    pub failure_count: u64,
    /// Current entries in buffer
    pub current_entries: usize,
    /// Buffer capacity
    pub capacity: usize,
    /// Whether buffer has wrapped
    pub has_wrapped: bool,
}

impl AuditStatsSnapshot {
    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_logged == 0 {
            return 100.0;
        }
        (self.success_count as f64 / self.total_logged as f64) * 100.0
    }
}

impl core::fmt::Display for AuditStatsSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Audit[total:{} ok:{} fail:{} buf:{}/{} wrapped:{}]",
            self.total_logged,
            self.success_count,
            self.failure_count,
            self.current_entries,
            self.capacity,
            self.has_wrapped
        )
    }
}

// ============================================================================
// Ring Buffer
// ============================================================================

/// Ring buffer for audit entries
struct AuditBuffer {
    /// Entry storage
    entries: Vec<AuditEntry>,
    /// Next write position
    write_pos: usize,
    /// Whether buffer has wrapped
    wrapped: bool,
}

impl AuditBuffer {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_LOG_ENTRIES),
            write_pos: 0,
            wrapped: false,
        }
    }

    /// Add an entry to the ring buffer
    fn push(&mut self, entry: AuditEntry) {
        if self.entries.len() < MAX_LOG_ENTRIES {
            // Still filling initial buffer
            self.entries.push(entry);
            self.write_pos = self.entries.len();
        } else {
            // Buffer full, overwrite oldest
            let pos = self.write_pos % MAX_LOG_ENTRIES;
            self.entries[pos] = entry;
            self.write_pos = pos + 1;
            self.wrapped = true;
        }
    }

    /// Get number of valid entries
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if buffer is empty
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entries in chronological order
    fn get_chronological(&self) -> Vec<AuditEntry> {
        if !self.wrapped {
            // Not wrapped yet, entries are already in order
            self.entries.clone()
        } else {
            // Wrapped: oldest is at write_pos, newest is at write_pos-1
            let pos = self.write_pos % MAX_LOG_ENTRIES;
            let mut result = Vec::with_capacity(self.entries.len());
            // Add from write_pos to end
            result.extend_from_slice(&self.entries[pos..]);
            // Add from start to write_pos
            result.extend_from_slice(&self.entries[..pos]);
            result
        }
    }

    /// Get the N most recent entries (in chronological order)
    fn get_recent(&self, count: usize) -> Vec<AuditEntry> {
        let all = self.get_chronological();
        let start = all.len().saturating_sub(count);
        all[start..].to_vec()
    }

    /// Clear all entries
    fn clear(&mut self) {
        self.entries.clear();
        self.write_pos = 0;
        self.wrapped = false;
    }

    /// Check if buffer has wrapped
    fn has_wrapped(&self) -> bool {
        self.wrapped
    }
}

// ============================================================================
// Global State
// ============================================================================

static BUFFER: Mutex<AuditBuffer> = Mutex::new(AuditBuffer {
    entries: Vec::new(),
    write_pos: 0,
    wrapped: false,
});

static STATS: AuditStats = AuditStats::new();

// ============================================================================
// Public API
// ============================================================================

/// Log a capability token use
///
/// Records the action in the audit ring buffer for later analysis.
/// Thread-safe and lock-free for statistics updates.
///
/// # Arguments
///
/// * `token` - The capability token being used
/// * `action` - Static string describing the action (e.g., "send_ipc", "alloc_page")
/// * `capability` - Specific capability being exercised (if applicable)
/// * `success` - Whether the action succeeded
pub fn log_use(
    token: &CapabilityToken,
    action: &'static str,
    capability: Option<Capability>,
    success: bool,
) {
    let entry = AuditEntry {
        timestamp_ms: crate::time::timestamp_millis(),
        owner_module: token.owner_module,
        action,
        capability,
        nonce: token.nonce,
        success,
    };

    // Update statistics first (lock-free)
    STATS.record(success);

    // Then add to buffer (requires lock)
    BUFFER.lock().push(entry);
}

/// Get all log entries in chronological order
///
/// Returns a clone of the entire log buffer. For large logs,
/// prefer `get_recent()` or `get_filtered()`.
pub fn get_log() -> Vec<AuditEntry> {
    BUFFER.lock().get_chronological()
}

/// Get the N most recent log entries
///
/// More efficient than `get_log()` when only recent entries are needed.
pub fn get_recent(count: usize) -> Vec<AuditEntry> {
    BUFFER.lock().get_recent(count)
}

/// Get entries filtered by module ID
pub fn get_by_module(module_id: u64) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.matches_module(module_id))
        .collect()
}

/// Get entries filtered by action
pub fn get_by_action(action: &str) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.matches_action(action))
        .collect()
}

/// Get entries within a time range
pub fn get_by_time_range(start_ms: u64, end_ms: u64) -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| e.in_time_range(start_ms, end_ms))
        .collect()
}

/// Get only failed entries
pub fn get_failures() -> Vec<AuditEntry> {
    BUFFER
        .lock()
        .get_chronological()
        .into_iter()
        .filter(|e| !e.success)
        .collect()
}

/// Get current log statistics
pub fn get_stats() -> AuditStatsSnapshot {
    let buf = BUFFER.lock();
    AuditStatsSnapshot {
        total_logged: STATS.total_logged.load(Ordering::Relaxed),
        success_count: STATS.success_count.load(Ordering::Relaxed),
        failure_count: STATS.failure_count.load(Ordering::Relaxed),
        current_entries: buf.len(),
        capacity: MAX_LOG_ENTRIES,
        has_wrapped: buf.has_wrapped(),
    }
}

/// Get current number of entries in the log
#[inline]
pub fn log_count() -> usize {
    BUFFER.lock().len()
}

/// Check if log is empty
#[inline]
pub fn is_empty() -> bool {
    BUFFER.lock().is_empty()
}

/// Clear all log entries
///
/// Does not reset statistics counters.
pub fn clear_log() {
    BUFFER.lock().clear();
}

/// Get the log capacity
#[inline]
pub const fn capacity() -> usize {
    MAX_LOG_ENTRIES
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_test_token(module: u64, nonce: u64) -> CapabilityToken {
        CapabilityToken {
            owner_module: module,
            permissions: vec![Capability::IPC],
            expires_at_ms: None,
            nonce,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_audit_entry_display() {
        let entry = AuditEntry {
            timestamp_ms: 1000,
            owner_module: 42,
            action: "test_action",
            capability: Some(Capability::IPC),
            nonce: 0x1234567890ABCDEF,
            success: true,
        };
        let s = alloc::format!("{}", entry);
        assert!(s.contains("1000"));
        assert!(s.contains("42"));
        assert!(s.contains("test_action"));
        assert!(s.contains("OK"));
    }

    #[test]
    fn test_audit_entry_matching() {
        let entry = AuditEntry {
            timestamp_ms: 5000,
            owner_module: 100,
            action: "send_msg",
            capability: None,
            nonce: 1,
            success: true,
        };

        assert!(entry.matches_module(100));
        assert!(!entry.matches_module(200));
        assert!(entry.matches_action("send_msg"));
        assert!(!entry.matches_action("recv_msg"));
        assert!(entry.in_time_range(4000, 6000));
        assert!(!entry.in_time_range(6000, 7000));
    }

    #[test]
    fn test_stats_snapshot_display() {
        let snap = AuditStatsSnapshot {
            total_logged: 100,
            success_count: 95,
            failure_count: 5,
            current_entries: 100,
            capacity: 4096,
            has_wrapped: false,
        };
        let s = alloc::format!("{}", snap);
        assert!(s.contains("100"));
        assert!(s.contains("95"));
        assert!(s.contains("5"));
    }

    #[test]
    fn test_stats_success_rate() {
        let snap = AuditStatsSnapshot {
            total_logged: 100,
            success_count: 80,
            failure_count: 20,
            current_entries: 100,
            capacity: 4096,
            has_wrapped: false,
        };
        assert!((snap.success_rate() - 80.0).abs() < 0.01);

        let empty = AuditStatsSnapshot::default();
        assert!((empty.success_rate() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_ring_buffer_no_wrap() {
        let mut buf = AuditBuffer::new();

        for i in 0..10 {
            buf.push(AuditEntry {
                timestamp_ms: i as u64,
                owner_module: 1,
                action: "test",
                capability: None,
                nonce: i as u64,
                success: true,
            });
        }

        assert_eq!(buf.len(), 10);
        assert!(!buf.has_wrapped());

        let entries = buf.get_chronological();
        assert_eq!(entries.len(), 10);
        assert_eq!(entries[0].timestamp_ms, 0);
        assert_eq!(entries[9].timestamp_ms, 9);
    }

    #[test]
    fn test_ring_buffer_get_recent() {
        let mut buf = AuditBuffer::new();

        for i in 0..100 {
            buf.push(AuditEntry {
                timestamp_ms: i as u64,
                owner_module: 1,
                action: "test",
                capability: None,
                nonce: i as u64,
                success: true,
            });
        }

        let recent = buf.get_recent(10);
        assert_eq!(recent.len(), 10);
        assert_eq!(recent[0].timestamp_ms, 90);
        assert_eq!(recent[9].timestamp_ms, 99);
    }
}
