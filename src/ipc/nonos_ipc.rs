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
//! PID-Based IPC Manager
//! # Architecture
//! Process A ──┐                    ┌── Process C
//!             │    ┌──────────┐    │
//!             ├───►│ Channel  │◄───┤
//!             │    │  Queue   │    │
//! Process B ──┘    └──────────┘    └── Process D

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Default queue capacity per channel
const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Maximum queue capacity
const MAX_QUEUE_CAPACITY: usize = 65536;

/// Maximum payload size (1 MB)
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Maximum participants per channel
const MAX_PARTICIPANTS: usize = 256;

// ============================================================================
// Error Types
// ============================================================================

/// IPC Manager errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcManagerError {
    /// Channel not found
    ChannelNotFound { channel_id: u64 },
    /// Sender not authorized for channel
    SenderNotAuthorized { sender_id: u64, channel_id: u64 },
    /// Recipient not authorized for channel
    RecipientNotAuthorized { recipient_id: u64, channel_id: u64 },
    /// Receiver not authorized for channel
    ReceiverNotAuthorized { receiver_id: u64, channel_id: u64 },
    /// Destroyer not authorized for channel
    DestroyerNotAuthorized { destroyer_id: u64, channel_id: u64 },
    /// Channel queue is full
    QueueFull { channel_id: u64, capacity: usize },
    /// No participants specified
    NoParticipants,
    /// Too many participants
    TooManyParticipants { count: usize, max: usize },
    /// Payload too large
    PayloadTooLarge { size: usize, max: usize },
    /// Channel ID collision (internal error)
    ChannelIdCollision { channel_id: u64 },
}

impl IpcManagerError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ChannelNotFound { .. } => "Channel not found",
            Self::SenderNotAuthorized { .. } => "Sender not authorized for channel",
            Self::RecipientNotAuthorized { .. } => "Recipient not authorized for channel",
            Self::ReceiverNotAuthorized { .. } => "Receiver not authorized for channel",
            Self::DestroyerNotAuthorized { .. } => "Destroyer not authorized for channel",
            Self::QueueFull { .. } => "Channel queue is full",
            Self::NoParticipants => "No participants specified",
            Self::TooManyParticipants { .. } => "Too many participants",
            Self::PayloadTooLarge { .. } => "Payload too large",
            Self::ChannelIdCollision { .. } => "Channel ID collision",
        }
    }
}

impl core::fmt::Display for IpcManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelNotFound { channel_id } => {
                write!(f, "Channel {} not found", channel_id)
            }
            Self::SenderNotAuthorized { sender_id, channel_id } => {
                write!(f, "Sender {} not authorized for channel {}", sender_id, channel_id)
            }
            Self::RecipientNotAuthorized { recipient_id, channel_id } => {
                write!(f, "Recipient {} not authorized for channel {}", recipient_id, channel_id)
            }
            Self::ReceiverNotAuthorized { receiver_id, channel_id } => {
                write!(f, "Receiver {} not authorized for channel {}", receiver_id, channel_id)
            }
            Self::DestroyerNotAuthorized { destroyer_id, channel_id } => {
                write!(f, "Process {} not authorized to destroy channel {}", destroyer_id, channel_id)
            }
            Self::QueueFull { channel_id, capacity } => {
                write!(f, "Channel {} queue full (capacity: {})", channel_id, capacity)
            }
            Self::NoParticipants => write!(f, "No participants specified"),
            Self::TooManyParticipants { count, max } => {
                write!(f, "Too many participants: {} (max: {})", count, max)
            }
            Self::PayloadTooLarge { size, max } => {
                write!(f, "Payload too large: {} bytes (max: {})", size, max)
            }
            Self::ChannelIdCollision { channel_id } => {
                write!(f, "Channel ID {} collision", channel_id)
            }
        }
    }
}

// ============================================================================
// Channel Types
// ============================================================================

/// Channel communication types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NonosChannelType {
    /// Shared memory region
    SharedMemory = 0x1000,
    /// Message passing queue
    MessagePassing = 0x2000,
    /// Signal delivery
    Signal = 0x3000,
    /// Pipe (unidirectional)
    Pipe = 0x4000,
    /// Socket-like bidirectional
    Socket = 0x5000,
}

impl NonosChannelType {
    /// Get channel type name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SharedMemory => "SharedMemory",
            Self::MessagePassing => "MessagePassing",
            Self::Signal => "Signal",
            Self::Pipe => "Pipe",
            Self::Socket => "Socket",
        }
    }

    /// Check if channel type supports bidirectional communication
    #[inline]
    pub fn is_bidirectional(&self) -> bool {
        matches!(self, Self::SharedMemory | Self::MessagePassing | Self::Socket)
    }
}

impl Default for NonosChannelType {
    fn default() -> Self {
        Self::MessagePassing
    }
}

impl core::fmt::Display for NonosChannelType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Message Types
// ============================================================================

/// Message classification for priority handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NonosMessageType {
    /// Regular data payload
    Data = 0x1000,
    /// Control/management message
    Control = 0x2000,
    /// Synchronization primitive
    Synchronization = 0x3000,
    /// Signal delivery
    Signal = 0x4000,
    /// Error notification
    Error = 0x5000,
}

impl NonosMessageType {
    /// Get message type name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "Data",
            Self::Control => "Control",
            Self::Synchronization => "Synchronization",
            Self::Signal => "Signal",
            Self::Error => "Error",
        }
    }

    /// Get priority for this message type (higher = more urgent)
    pub const fn priority(&self) -> u8 {
        match self {
            Self::Control => 255,
            Self::Signal => 200,
            Self::Error => 180,
            Self::Synchronization => 150,
            Self::Data => 100,
        }
    }

    /// Check if this is a high-priority message type
    #[inline]
    pub fn is_high_priority(&self) -> bool {
        self.priority() >= 150
    }
}

impl Default for NonosMessageType {
    fn default() -> Self {
        Self::Data
    }
}

impl core::fmt::Display for NonosMessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// IPC Message
// ============================================================================

/// IPC message structure
#[derive(Debug, Clone)]
pub struct NonosIPCMessage {
    /// Unique message identifier
    pub message_id: u64,
    /// Sender process ID
    pub sender_id: u64,
    /// Recipient process ID
    pub recipient_id: u64,
    /// Message classification
    pub message_type: NonosMessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Creation timestamp (milliseconds since boot)
    pub timestamp_ms: u64,
    /// Message priority (derived from type)
    pub priority: u8,
}

impl NonosIPCMessage {
    /// Get payload length
    #[inline]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Check if payload is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Get message age in milliseconds
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.timestamp_ms)
    }
}

// ============================================================================
// Channel Queue
// ============================================================================

/// Bounded message queue for a channel
#[derive(Debug, Clone)]
struct ChannelQueue {
    queue: VecDeque<NonosIPCMessage>,
    capacity: usize,
}

impl ChannelQueue {
    fn new(capacity: usize) -> Self {
        let cap = capacity.min(MAX_QUEUE_CAPACITY);
        Self {
            queue: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.queue.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.queue.len() >= self.capacity
    }

    fn push(&mut self, msg: NonosIPCMessage) -> Result<(), usize> {
        if self.is_full() {
            Err(self.capacity)
        } else {
            self.queue.push_back(msg);
            Ok(())
        }
    }

    fn pop_for(&mut self, receiver_id: u64) -> Option<NonosIPCMessage> {
        if let Some(pos) = self.queue.iter().position(|m| m.recipient_id == receiver_id) {
            self.queue.remove(pos)
        } else {
            None
        }
    }

    fn peek_for(&self, receiver_id: u64) -> Option<&NonosIPCMessage> {
        self.queue.iter().find(|m| m.recipient_id == receiver_id)
    }

    fn count_for(&self, receiver_id: u64) -> usize {
        self.queue.iter().filter(|m| m.recipient_id == receiver_id).count()
    }
}

// ============================================================================
// IPC Channel
// ============================================================================

/// IPC channel with metadata and message queue
#[derive(Debug)]
pub struct NonosIPCChannel {
    /// Unique channel identifier
    pub channel_id: u64,
    /// Channel type
    pub channel_type: NonosChannelType,
    /// Allowed participant PIDs
    pub participants: Vec<u64>,
    /// Whether encryption is enabled
    pub encryption_enabled: bool,
    /// Message queue
    queue: Mutex<ChannelQueue>,
}

impl NonosIPCChannel {
    fn new(
        channel_id: u64,
        channel_type: NonosChannelType,
        participants: Vec<u64>,
        capacity: usize,
    ) -> Self {
        Self {
            channel_id,
            channel_type,
            participants,
            encryption_enabled: false,
            queue: Mutex::new(ChannelQueue::new(capacity)),
        }
    }

    /// Check if a process is a participant
    #[inline]
    pub fn has_participant(&self, pid: u64) -> bool {
        self.participants.contains(&pid)
    }

    /// Get number of participants
    #[inline]
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Get queue length
    pub fn queue_len(&self) -> usize {
        self.queue.lock().len()
    }

    /// Check if queue is empty
    pub fn is_queue_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    /// Count messages pending for a receiver
    pub fn pending_for(&self, receiver_id: u64) -> usize {
        self.queue.lock().count_for(receiver_id)
    }
}

impl Clone for NonosIPCChannel {
    fn clone(&self) -> Self {
        Self {
            channel_id: self.channel_id,
            channel_type: self.channel_type,
            participants: self.participants.clone(),
            encryption_enabled: self.encryption_enabled,
            queue: Mutex::new(self.queue.lock().clone()),
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// IPC Manager statistics
struct ManagerStats {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    messages_dropped: AtomicU64,
    channels_created: AtomicU64,
    channels_destroyed: AtomicU64,
}

impl ManagerStats {
    const fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            channels_created: AtomicU64::new(0),
            channels_destroyed: AtomicU64::new(0),
        }
    }
}

/// Statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct ManagerStatsSnapshot {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub channels_created: u64,
    pub channels_destroyed: u64,
    pub active_channels: usize,
}

// ============================================================================
// IPC Manager
// ============================================================================

/// PID-oriented IPC manager
pub struct NonosIPCManager {
    /// Active channels
    channels: RwLock<BTreeMap<u64, NonosIPCChannel>>,
    /// Process to channel mapping
    process_channels: RwLock<BTreeMap<u64, Vec<u64>>>,
    /// Next channel ID
    next_channel_id: AtomicU64,
    /// Next message ID
    next_message_id: AtomicU64,
    /// Default queue capacity
    default_queue_cap: AtomicU64,
    /// Statistics
    stats: ManagerStats,
}

impl NonosIPCManager {
    /// Create a new IPC manager
    pub const fn new() -> Self {
        Self {
            channels: RwLock::new(BTreeMap::new()),
            process_channels: RwLock::new(BTreeMap::new()),
            next_channel_id: AtomicU64::new(1),
            next_message_id: AtomicU64::new(1),
            default_queue_cap: AtomicU64::new(DEFAULT_QUEUE_CAPACITY as u64),
            stats: ManagerStats::new(),
        }
    }

    /// Set default queue capacity for new channels
    pub fn set_default_queue_capacity(&self, capacity: usize) {
        let cap = capacity.min(MAX_QUEUE_CAPACITY);
        self.default_queue_cap.store(cap as u64, Ordering::Relaxed);
    }

    /// Get default queue capacity
    pub fn default_queue_capacity(&self) -> usize {
        self.default_queue_cap.load(Ordering::Relaxed) as usize
    }

    /// Create a channel between participants
    ///
    /// The creator must be included in participants (auto-added if missing).
    pub fn create_channel(
        &self,
        creator_id: u64,
        channel_type: NonosChannelType,
        mut participants: Vec<u64>,
    ) -> Result<u64, IpcManagerError> {
        // Ensure creator is a participant
        if !participants.contains(&creator_id) {
            participants.push(creator_id);
        }

        // Validate participants
        if participants.is_empty() {
            return Err(IpcManagerError::NoParticipants);
        }
        if participants.len() > MAX_PARTICIPANTS {
            return Err(IpcManagerError::TooManyParticipants {
                count: participants.len(),
                max: MAX_PARTICIPANTS,
            });
        }

        let channel_id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        let capacity = self.default_queue_cap.load(Ordering::Relaxed) as usize;

        let channel = NonosIPCChannel::new(channel_id, channel_type, participants.clone(), capacity);

        // Insert channel
        {
            let mut ch_map = self.channels.write();
            if ch_map.contains_key(&channel_id) {
                return Err(IpcManagerError::ChannelIdCollision { channel_id });
            }
            ch_map.insert(channel_id, channel);
        }

        // Update process-channel mappings
        {
            let mut proc_map = self.process_channels.write();
            for pid in participants {
                proc_map.entry(pid).or_insert_with(Vec::new).push(channel_id);
            }
        }

        self.stats.channels_created.fetch_add(1, Ordering::Relaxed);
        Ok(channel_id)
    }

    /// Send a message on a channel
    ///
    /// Both sender and recipient must be channel participants.
    pub fn send_message(
        &self,
        sender_id: u64,
        channel_id: u64,
        recipient_id: u64,
        message_type: NonosMessageType,
        payload: Vec<u8>,
    ) -> Result<u64, IpcManagerError> {
        // Validate payload size
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(IpcManagerError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let msg_id = self.next_message_id.fetch_add(1, Ordering::Relaxed);
        let now = crate::time::timestamp_millis();

        let mut ch_map = self.channels.write();
        let channel = ch_map.get_mut(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;

        // Check authorization
        if !channel.has_participant(sender_id) {
            return Err(IpcManagerError::SenderNotAuthorized { sender_id, channel_id });
        }
        if !channel.has_participant(recipient_id) {
            return Err(IpcManagerError::RecipientNotAuthorized { recipient_id, channel_id });
        }

        let msg = NonosIPCMessage {
            message_id: msg_id,
            sender_id,
            recipient_id,
            message_type,
            payload,
            timestamp_ms: now,
            priority: message_type.priority(),
        };

        // Enqueue message
        let mut queue = channel.queue.lock();
        match queue.push(msg) {
            Ok(()) => {
                self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                Ok(msg_id)
            }
            Err(capacity) => {
                self.stats.messages_dropped.fetch_add(1, Ordering::Relaxed);
                Err(IpcManagerError::QueueFull { channel_id, capacity })
            }
        }
    }

    /// Receive the next message for a receiver on a channel
    pub fn receive_message(
        &self,
        receiver_id: u64,
        channel_id: u64,
    ) -> Result<Option<NonosIPCMessage>, IpcManagerError> {
        let mut ch_map = self.channels.write();
        let channel = ch_map.get_mut(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;

        if !channel.has_participant(receiver_id) {
            return Err(IpcManagerError::ReceiverNotAuthorized { receiver_id, channel_id });
        }

        let result = channel.queue.lock().pop_for(receiver_id);
        if result.is_some() {
            self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    /// Peek at the next message without removing it
    pub fn peek_message(
        &self,
        receiver_id: u64,
        channel_id: u64,
    ) -> Result<Option<NonosIPCMessage>, IpcManagerError> {
        let ch_map = self.channels.read();
        let channel = ch_map.get(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;

        if !channel.has_participant(receiver_id) {
            return Err(IpcManagerError::ReceiverNotAuthorized { receiver_id, channel_id });
        }

        Ok(channel.queue.lock().peek_for(receiver_id).cloned())
    }

    /// Destroy a channel
    ///
    /// Only participants can destroy a channel.
    pub fn destroy_channel(
        &self,
        destroyer_id: u64,
        channel_id: u64,
    ) -> Result<(), IpcManagerError> {
        let participants = {
            let ch_map = self.channels.read();
            let channel = ch_map.get(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;

            if !channel.has_participant(destroyer_id) {
                return Err(IpcManagerError::DestroyerNotAuthorized { destroyer_id, channel_id });
            }
            channel.participants.clone()
        };

        // Remove channel
        self.channels.write().remove(&channel_id);

        // Remove from process mappings
        {
            let mut proc_map = self.process_channels.write();
            for pid in participants {
                if let Some(list) = proc_map.get_mut(&pid) {
                    list.retain(|&cid| cid != channel_id);
                    if list.is_empty() {
                        proc_map.remove(&pid);
                    }
                }
            }
        }

        self.stats.channels_destroyed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Get channel count
    #[inline]
    pub fn channel_count(&self) -> usize {
        self.channels.read().len()
    }

    /// Get channels for a process
    pub fn get_process_channels(&self, process_id: u64) -> Vec<u64> {
        self.process_channels
            .read()
            .get(&process_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get channel info
    pub fn get_channel(&self, channel_id: u64) -> Option<NonosIPCChannel> {
        self.channels.read().get(&channel_id).cloned()
    }

    /// Get statistics snapshot
    pub fn get_stats(&self) -> ManagerStatsSnapshot {
        ManagerStatsSnapshot {
            messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
            messages_received: self.stats.messages_received.load(Ordering::Relaxed),
            messages_dropped: self.stats.messages_dropped.load(Ordering::Relaxed),
            channels_created: self.stats.channels_created.load(Ordering::Relaxed),
            channels_destroyed: self.stats.channels_destroyed.load(Ordering::Relaxed),
            active_channels: self.channel_count(),
        }
    }

    /// Clean up channels for a terminated process
    pub fn cleanup_process(&self, process_id: u64) {
        let channel_ids = self.get_process_channels(process_id);
        for channel_id in channel_ids {
            // Try to destroy - ignore errors if already destroyed
            let _ = self.destroy_channel(process_id, channel_id);
        }
    }
}

impl Default for NonosIPCManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Instance
// ============================================================================

/// Global IPC manager instance
pub static NONOS_IPC_MANAGER: NonosIPCManager = NonosIPCManager::new();

/// Get the global IPC manager
#[inline]
pub fn get_ipc_manager() -> &'static NonosIPCManager {
    &NONOS_IPC_MANAGER
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Create an IPC channel
pub fn create_ipc_channel(
    creator_id: u64,
    channel_type: NonosChannelType,
    participants: Vec<u64>,
) -> Result<u64, IpcManagerError> {
    NONOS_IPC_MANAGER.create_channel(creator_id, channel_type, participants)
}

/// Send an IPC message
pub fn send_ipc_message(
    sender_id: u64,
    channel_id: u64,
    recipient_id: u64,
    message_type: NonosMessageType,
    payload: Vec<u8>,
) -> Result<u64, IpcManagerError> {
    NONOS_IPC_MANAGER.send_message(sender_id, channel_id, recipient_id, message_type, payload)
}

/// Receive an IPC message
pub fn receive_ipc_message(
    receiver_id: u64,
    channel_id: u64,
) -> Result<Option<NonosIPCMessage>, IpcManagerError> {
    NONOS_IPC_MANAGER.receive_message(receiver_id, channel_id)
}

/// Destroy an IPC channel
pub fn destroy_ipc_channel(
    destroyer_id: u64,
    channel_id: u64,
) -> Result<(), IpcManagerError> {
    NONOS_IPC_MANAGER.destroy_channel(destroyer_id, channel_id)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_type_display() {
        assert_eq!(format!("{}", NonosChannelType::MessagePassing), "MessagePassing");
        assert_eq!(format!("{}", NonosChannelType::Pipe), "Pipe");
    }

    #[test]
    fn test_channel_type_bidirectional() {
        assert!(NonosChannelType::MessagePassing.is_bidirectional());
        assert!(NonosChannelType::Socket.is_bidirectional());
        assert!(!NonosChannelType::Pipe.is_bidirectional());
        assert!(!NonosChannelType::Signal.is_bidirectional());
    }

    #[test]
    fn test_message_type_priority() {
        assert!(NonosMessageType::Control.priority() > NonosMessageType::Data.priority());
        assert!(NonosMessageType::Signal.priority() > NonosMessageType::Data.priority());
        assert!(NonosMessageType::Control.is_high_priority());
        assert!(!NonosMessageType::Data.is_high_priority());
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", NonosMessageType::Data), "Data");
        assert_eq!(format!("{}", NonosMessageType::Control), "Control");
    }

    #[test]
    fn test_channel_queue_capacity() {
        let mut queue = ChannelQueue::new(3);
        assert!(queue.is_empty());
        assert!(!queue.is_full());

        for i in 0..3 {
            let msg = NonosIPCMessage {
                message_id: i,
                sender_id: 1,
                recipient_id: 2,
                message_type: NonosMessageType::Data,
                payload: vec![],
                timestamp_ms: 0,
                priority: 100,
            };
            assert!(queue.push(msg).is_ok());
        }

        assert!(queue.is_full());
        assert_eq!(queue.len(), 3);

        // Should fail when full
        let msg = NonosIPCMessage {
            message_id: 99,
            sender_id: 1,
            recipient_id: 2,
            message_type: NonosMessageType::Data,
            payload: vec![],
            timestamp_ms: 0,
            priority: 100,
        };
        assert!(queue.push(msg).is_err());
    }

    #[test]
    fn test_channel_queue_pop_for() {
        let mut queue = ChannelQueue::new(10);

        // Add messages for different recipients
        for (i, recipient) in [1u64, 2, 1, 3, 2].iter().enumerate() {
            let msg = NonosIPCMessage {
                message_id: i as u64,
                sender_id: 0,
                recipient_id: *recipient,
                message_type: NonosMessageType::Data,
                payload: vec![],
                timestamp_ms: 0,
                priority: 100,
            };
            queue.push(msg).unwrap();
        }

        // Pop for recipient 2 should get message_id 1 (first for recipient 2)
        let msg = queue.pop_for(2).unwrap();
        assert_eq!(msg.message_id, 1);
        assert_eq!(msg.recipient_id, 2);

        // Next pop for recipient 2 should get message_id 4
        let msg = queue.pop_for(2).unwrap();
        assert_eq!(msg.message_id, 4);

        // No more messages for recipient 2
        assert!(queue.pop_for(2).is_none());
    }

    #[test]
    fn test_error_display() {
        let e = IpcManagerError::ChannelNotFound { channel_id: 42 };
        assert!(format!("{}", e).contains("42"));

        let e = IpcManagerError::PayloadTooLarge { size: 2000000, max: 1000000 };
        let msg = format!("{}", e);
        assert!(msg.contains("2000000"));
        assert!(msg.contains("1000000"));
    }

    #[test]
    fn test_message_helpers() {
        let msg = NonosIPCMessage {
            message_id: 1,
            sender_id: 10,
            recipient_id: 20,
            message_type: NonosMessageType::Data,
            payload: vec![1, 2, 3, 4, 5],
            timestamp_ms: 0,
            priority: 100,
        };

        assert_eq!(msg.len(), 5);
        assert!(!msg.is_empty());
    }
}
