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
//! IPC Channel and Message Bus
//! The IPC bus maintains a registry of channels (routes between modules).
//! Messages are enqueued on the bus and later dequeued for delivery.
//! Each channel is identified by a BLAKE3-derived key for fast lookup.
//!
//! # RAM-Only Design
//!
//! All channel state is held in memory. No persistence layer exists.
//! On system reset, all channels and queued messages are lost.

extern crate alloc;

use alloc::{collections::VecDeque, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum queue size
pub const DEFAULT_MAX_QUEUE: usize = 4096;

/// Default message timeout in milliseconds
pub const DEFAULT_MSG_TIMEOUT_MS: u64 = 5_000;

/// Maximum message payload size (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// ============================================================================
// Channel Error
// ============================================================================

/// Channel operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Channel not found
    NotFound { from: String, to: String },
    /// Queue is full
    QueueFull { queue_size: usize, max_size: usize },
    /// Message too large
    MessageTooLarge { size: usize, max: usize },
    /// Channel already exists
    AlreadyExists { from: String, to: String },
    /// Invalid channel endpoints
    InvalidEndpoints,
    /// Message integrity check failed
    IntegrityCheckFailed,
}

impl ChannelError {
    /// Get a short description of the error
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "Channel not found",
            Self::QueueFull { .. } => "Queue full",
            Self::MessageTooLarge { .. } => "Message too large",
            Self::AlreadyExists { .. } => "Channel exists",
            Self::InvalidEndpoints => "Invalid endpoints",
            Self::IntegrityCheckFailed => "Integrity check failed",
        }
    }
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound { from, to } => {
                write!(f, "Channel not found: {} -> {}", from, to)
            }
            Self::QueueFull { queue_size, max_size } => {
                write!(f, "Queue full: {}/{} messages", queue_size, max_size)
            }
            Self::MessageTooLarge { size, max } => {
                write!(f, "Message too large: {} bytes (max: {})", size, max)
            }
            Self::AlreadyExists { from, to } => {
                write!(f, "Channel already exists: {} -> {}", from, to)
            }
            Self::InvalidEndpoints => write!(f, "Invalid channel endpoints"),
            Self::IntegrityCheckFailed => write!(f, "Message integrity check failed"),
        }
    }
}

// ============================================================================
// Bus Statistics
// ============================================================================

/// Global bus statistics
struct BusStats {
    messages_enqueued: AtomicU64,
    messages_dequeued: AtomicU64,
    messages_timed_out: AtomicU64,
    channels_opened: AtomicU64,
    channels_closed: AtomicU64,
    bytes_transferred: AtomicU64,
    queue_full_rejections: AtomicU64,
}

impl BusStats {
    const fn new() -> Self {
        Self {
            messages_enqueued: AtomicU64::new(0),
            messages_dequeued: AtomicU64::new(0),
            messages_timed_out: AtomicU64::new(0),
            channels_opened: AtomicU64::new(0),
            channels_closed: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            queue_full_rejections: AtomicU64::new(0),
        }
    }
}

/// Snapshot of bus statistics
#[derive(Debug, Clone, Copy)]
pub struct BusStatsSnapshot {
    /// Total messages enqueued
    pub messages_enqueued: u64,
    /// Total messages dequeued
    pub messages_dequeued: u64,
    /// Total messages that timed out
    pub messages_timed_out: u64,
    /// Total channels opened
    pub channels_opened: u64,
    /// Total channels closed
    pub channels_closed: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Queue full rejections
    pub queue_full_rejections: u64,
    /// Current queue depth
    pub current_queue_depth: usize,
    /// Current channel count
    pub current_channel_count: usize,
}

impl core::fmt::Display for BusStatsSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Bus[enq:{} deq:{} timeout:{} ch:{}/{} bytes:{} reject:{}]",
            self.messages_enqueued,
            self.messages_dequeued,
            self.messages_timed_out,
            self.current_channel_count,
            self.channels_opened,
            self.bytes_transferred,
            self.queue_full_rejections
        )
    }
}

// ============================================================================
// IPC Message
// ============================================================================

/// IPC message with integrity checksum
///
/// Messages are validated using a BLAKE3-based checksum that covers
/// the sender, receiver, payload, and timestamp.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    /// Source module identifier
    pub from: String,
    /// Destination module identifier
    pub to: String,
    /// Message payload
    pub data: Vec<u8>,
    /// Creation timestamp (milliseconds since boot)
    pub timestamp_ms: u64,
    /// Integrity checksum
    checksum64: u64,
}

impl IpcMessage {
    /// Create a new message with computed checksum
    pub fn new(from: &str, to: &str, data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err("Message payload too large");
        }

        let ts = crate::time::timestamp_millis();
        let csum = compute_checksum(from, to, data, ts);

        Ok(Self {
            from: String::from(from),
            to: String::from(to),
            data: data.to_vec(),
            timestamp_ms: ts,
            checksum64: csum,
        })
    }

    /// Create a message with custom timestamp (for testing)
    #[cfg(test)]
    pub fn with_timestamp(from: &str, to: &str, data: &[u8], ts: u64) -> Self {
        let csum = compute_checksum(from, to, data, ts);
        Self {
            from: String::from(from),
            to: String::from(to),
            data: data.to_vec(),
            timestamp_ms: ts,
            checksum64: csum,
        }
    }

    /// Validate message integrity
    #[inline]
    pub fn validate_integrity(&self) -> bool {
        self.checksum64 == compute_checksum(&self.from, &self.to, &self.data, self.timestamp_ms)
    }

    /// Get message age in milliseconds
    #[inline]
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.timestamp_ms)
    }

    /// Get payload size
    #[inline]
    pub fn payload_size(&self) -> usize {
        self.data.len()
    }

    /// Check if message is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl core::fmt::Display for IpcMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "IpcMessage[{} -> {}, {} bytes, {}ms old]",
            self.from,
            self.to,
            self.data.len(),
            self.age_ms()
        )
    }
}

// ============================================================================
// Channel Entry
// ============================================================================

/// Internal channel registry entry
struct ChannelEntry {
    /// Source module
    from: String,
    /// Destination module
    to: String,
    /// Channel key (hash of from+to)
    key: u64,
    /// Whether channel is alive
    alive: AtomicBool,
    /// Last activity timestamp
    last_active_ms: AtomicU64,
    /// Messages sent through this channel
    messages_sent: AtomicU64,
}

impl ChannelEntry {
    fn new(from: &str, to: &str) -> Self {
        Self {
            from: String::from(from),
            to: String::from(to),
            key: compute_channel_key(from, to),
            alive: AtomicBool::new(true),
            last_active_ms: AtomicU64::new(crate::time::timestamp_millis()),
            messages_sent: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        self.last_active_ms.store(crate::time::timestamp_millis(), Ordering::Relaxed);
        self.alive.store(true, Ordering::Relaxed);
    }

    fn record_send(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }
}

// ============================================================================
// IPC Channel Handle
// ============================================================================

/// Handle to a registered IPC route
///
/// Lightweight, copyable handle that can be used to send messages
/// on a registered channel.
#[derive(Clone, Copy)]
pub struct IpcChannel {
    /// Channel key
    key: u64,
}

impl IpcChannel {
    /// Send a message on this channel
    #[inline]
    pub fn send(&self, msg: IpcMessage) -> Result<(), &'static str> {
        IPC_BUS.enqueue(self.key, msg)
    }

    /// Get the channel key
    #[inline]
    pub fn key(&self) -> u64 {
        self.key
    }
}

impl core::fmt::Debug for IpcChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IpcChannel(key=0x{:016x})", self.key)
    }
}

// ============================================================================
// IPC Bus
// ============================================================================

/// Global IPC message bus
///
/// Manages channel registration and message queuing.
/// All operations are thread-safe using spin locks.
pub struct IpcBus {
    /// Registered channels
    channels: RwLock<Vec<ChannelEntry>>,
    /// Message queue (key, message)
    queue: Mutex<VecDeque<(u64, IpcMessage)>>,
    /// Maximum queue size
    max_queue: usize,
    /// Message timeout in milliseconds
    msg_timeout_ms: u64,
    /// Statistics
    stats: BusStats,
}

impl IpcBus {
    /// Create a new IPC bus
    pub const fn new() -> Self {
        Self {
            channels: RwLock::new(Vec::new()),
            queue: Mutex::new(VecDeque::new()),
            max_queue: DEFAULT_MAX_QUEUE,
            msg_timeout_ms: DEFAULT_MSG_TIMEOUT_MS,
            stats: BusStats::new(),
        }
    }

    /// Register a new channel route
    pub fn open_channel(
        &self,
        from: &str,
        to: &str,
        _token: &crate::syscall::capabilities::CapabilityToken,
    ) -> Result<(), &'static str> {
        if from.is_empty() || to.is_empty() {
            return Err("Invalid channel endpoints");
        }

        let mut ch = self.channels.write();

        // Check if channel already exists
        if ch.iter().any(|c| c.from == from && c.to == to) {
            return Ok(()); // Idempotent
        }

        ch.push(ChannelEntry::new(from, to));
        self.stats.channels_opened.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Find a channel handle by endpoints
    pub fn find_channel(&self, from: impl AsRef<str>, to: impl AsRef<str>) -> Option<IpcChannel> {
        let f = from.as_ref();
        let t = to.as_ref();
        let key = compute_channel_key(f, t);

        let ch = self.channels.read();
        if ch.iter().any(|c| c.key == key && c.alive.load(Ordering::Relaxed)) {
            Some(IpcChannel { key })
        } else {
            None
        }
    }

    /// Check if a channel exists
    pub fn channel_exists(&self, from: &str, to: &str) -> bool {
        let key = compute_channel_key(from, to);
        let ch = self.channels.read();
        ch.iter().any(|c| c.key == key)
    }

    /// Enqueue a message for processing
    pub fn enqueue(&self, key: u64, msg: IpcMessage) -> Result<(), &'static str> {
        // Update channel activity
        if let Some(c) = self.channels.read().iter().find(|c| c.key == key) {
            c.record_send();
        }

        let bytes = msg.data.len() as u64;

        let mut q = self.queue.lock();
        if q.len() >= self.max_queue {
            self.stats.queue_full_rejections.fetch_add(1, Ordering::Relaxed);
            return Err("IPC queue full");
        }

        q.push_back((key, msg));
        drop(q);

        self.stats.messages_enqueued.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);

        Ok(())
    }

    /// Pop the next message from the queue
    pub fn get_next_message(&self) -> Option<IpcMessage> {
        let mut q = self.queue.lock();
        let result = q.pop_front().map(|(_key, msg)| msg);

        if result.is_some() {
            self.stats.messages_dequeued.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Get and remove messages that exceeded timeout
    pub fn get_timed_out_messages(&self) -> Vec<IpcMessage> {
        let now = crate::time::timestamp_millis();
        let mut q = self.queue.lock();
        let mut out = Vec::new();
        let mut remain = VecDeque::with_capacity(q.len());

        while let Some((key, msg)) = q.pop_front() {
            if now.saturating_sub(msg.timestamp_ms) > self.msg_timeout_ms {
                out.push(msg);
                self.stats.messages_timed_out.fetch_add(1, Ordering::Relaxed);

                // Mark channel as potentially dead
                if let Some(c) = self.channels.read().iter().find(|c| c.key == key) {
                    c.alive.store(false, Ordering::Relaxed);
                }
            } else {
                remain.push_back((key, msg));
            }
        }

        *q = remain;
        out
    }

    /// Find channels marked as dead
    pub fn find_dead_channels(&self) -> Vec<usize> {
        let ch = self.channels.read();
        ch.iter()
            .enumerate()
            .filter(|(_i, c)| !c.alive.load(Ordering::Relaxed))
            .map(|(i, _)| i)
            .collect()
    }

    /// Remove a channel by index
    pub fn remove_channel(&self, index: usize) {
        let mut ch = self.channels.write();
        if index < ch.len() {
            ch.remove(index);
            self.stats.channels_closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove all channels for a module
    pub fn remove_all_channels_for_module(&self, module: &str) {
        let mut ch = self.channels.write();
        let before = ch.len();
        ch.retain(|c| c.from != module && c.to != module);
        let removed = before - ch.len();
        self.stats.channels_closed.fetch_add(removed as u64, Ordering::Relaxed);
    }

    /// List all routes as (from, to) pairs
    pub fn list_routes(&self) -> Vec<(String, String)> {
        self.channels
            .read()
            .iter()
            .map(|c| (c.from.clone(), c.to.clone()))
            .collect()
    }

    /// Get active channel count
    pub fn get_active_channel_count(&self) -> usize {
        self.channels.read().len()
    }

    /// Get current queue depth
    pub fn get_queue_depth(&self) -> usize {
        self.queue.lock().len()
    }

    /// Send a system message without capability checks
    ///
    /// Used for kernel-originated notifications.
    pub fn send_system_message(
        &self,
        env: super::nonos_message::IpcEnvelope,
    ) -> Result<(), &'static str> {
        let key = compute_channel_key(&env.from, &env.to);
        let msg = IpcMessage::new(&env.from, &env.to, &env.data)?;
        self.enqueue(key, msg)
    }

    /// Get bus statistics snapshot
    pub fn get_stats(&self) -> BusStatsSnapshot {
        BusStatsSnapshot {
            messages_enqueued: self.stats.messages_enqueued.load(Ordering::Relaxed),
            messages_dequeued: self.stats.messages_dequeued.load(Ordering::Relaxed),
            messages_timed_out: self.stats.messages_timed_out.load(Ordering::Relaxed),
            channels_opened: self.stats.channels_opened.load(Ordering::Relaxed),
            channels_closed: self.stats.channels_closed.load(Ordering::Relaxed),
            bytes_transferred: self.stats.bytes_transferred.load(Ordering::Relaxed),
            queue_full_rejections: self.stats.queue_full_rejections.load(Ordering::Relaxed),
            current_queue_depth: self.get_queue_depth(),
            current_channel_count: self.get_active_channel_count(),
        }
    }
}

// ============================================================================
// Hash Functions
// ============================================================================

/// Compute channel key from endpoints using BLAKE3
#[inline]
fn compute_channel_key(from: &str, to: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0x00]); // Separator
    hasher.update(to.as_bytes());

    let out = hasher.finalize();
    let bytes = out.as_bytes();

    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Compute message checksum using BLAKE3
#[inline]
fn compute_checksum(from: &str, to: &str, data: &[u8], ts_ms: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(from.as_bytes());
    hasher.update(&[0xF0]); // Separator
    hasher.update(to.as_bytes());
    hasher.update(&ts_ms.to_le_bytes());
    hasher.update(data);

    let out = hasher.finalize();
    let b = out.as_bytes();

    // Use bytes from different position than channel key
    u64::from_le_bytes([
        b[24], b[25], b[26], b[27],
        b[28], b[29], b[30], b[31],
    ])
}

// ============================================================================
// Global Instance
// ============================================================================

/// Global IPC bus instance
pub static IPC_BUS: IpcBus = IpcBus::new();

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_error_display() {
        let e = ChannelError::NotFound {
            from: "a".into(),
            to: "b".into(),
        };
        let msg = format!("{}", e);
        assert!(msg.contains("a"));
        assert!(msg.contains("b"));

        let e = ChannelError::QueueFull {
            queue_size: 100,
            max_size: 100,
        };
        assert!(format!("{}", e).contains("100"));

        let e = ChannelError::MessageTooLarge {
            size: 2000000,
            max: 1000000,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("2000000"));
        assert!(msg.contains("1000000"));

        let e = ChannelError::AlreadyExists {
            from: "x".into(),
            to: "y".into(),
        };
        assert!(format!("{}", e).contains("exists"));

        let e = ChannelError::InvalidEndpoints;
        assert!(format!("{}", e).contains("Invalid"));

        let e = ChannelError::IntegrityCheckFailed;
        assert!(format!("{}", e).contains("integrity"));
    }

    #[test]
    fn test_bus_stats_display() {
        let snap = BusStatsSnapshot {
            messages_enqueued: 100,
            messages_dequeued: 90,
            messages_timed_out: 5,
            channels_opened: 10,
            channels_closed: 2,
            bytes_transferred: 50000,
            queue_full_rejections: 3,
            current_queue_depth: 10,
            current_channel_count: 8,
        };
        let s = format!("{}", snap);
        assert!(s.contains("100"));
        assert!(s.contains("90"));
        assert!(s.contains("50000"));
    }

    #[test]
    fn test_ipc_message_display() {
        let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
        let s = format!("{}", msg);
        assert!(s.contains("sender"));
        assert!(s.contains("receiver"));
        assert!(s.contains("5 bytes"));
    }

    #[test]
    fn test_channel_key_deterministic() {
        let key1 = compute_channel_key("alice", "bob");
        let key2 = compute_channel_key("alice", "bob");
        assert_eq!(key1, key2);

        // Different endpoints should give different keys
        let key3 = compute_channel_key("bob", "alice");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_message_checksum() {
        let msg = IpcMessage::with_timestamp("a", "b", b"test", 12345);
        assert!(msg.validate_integrity());
    }

    #[test]
    fn test_message_size_limit() {
        let large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = IpcMessage::new("a", "b", &large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_entry_creation() {
        let entry = ChannelEntry::new("from", "to");
        assert_eq!(entry.from, "from");
        assert_eq!(entry.to, "to");
        assert!(entry.alive.load(Ordering::Relaxed));
    }

    #[test]
    fn test_ipc_channel_debug() {
        let channel = IpcChannel { key: 0x123456789ABCDEF0 };
        let s = format!("{:?}", channel);
        assert!(s.contains("123456789abcdef0"));
    }
}
