// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

//! Global inbox registry.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::RwLock;

use crate::ipc::nonos_channel::IpcMessage;
use super::error::InboxError;
use super::inbox::Inbox;
use super::stats::InboxStatsSnapshot;

/// Default inbox capacity (messages)
pub const DEFAULT_INBOX_CAPACITY: usize = 1024;

/// Minimum inbox capacity
pub const MIN_INBOX_CAPACITY: usize = 16;

/// Maximum inbox capacity
pub const MAX_INBOX_CAPACITY: usize = 65536;

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
pub fn list_inboxes() -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_register_with_invalid_capacity() {
        let result = register_inbox_with_capacity("test_mod", 5);
        assert!(matches!(result, Err(InboxError::InvalidCapacity { .. })));

        let result = register_inbox_with_capacity("", 100);
        assert!(matches!(result, Err(InboxError::EmptyModuleName)));
    }
}
