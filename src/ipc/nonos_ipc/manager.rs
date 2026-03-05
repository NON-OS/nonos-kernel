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

//! PID-oriented IPC manager.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::channel::NonosIPCChannel;
use super::error::IpcManagerError;
use super::types::{NonosChannelType, NonosIPCMessage, NonosMessageType};

/// Default queue capacity per channel
const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Maximum queue capacity
const MAX_QUEUE_CAPACITY: usize = 65536;

/// Maximum payload size (1 MB)
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Maximum participants per channel
const MAX_PARTICIPANTS: usize = 256;

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

        let result = channel.queue.lock().peek_for(receiver_id).cloned();
        drop(ch_map);
        Ok(result)
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

/// Global IPC manager instance
pub static NONOS_IPC_MANAGER: NonosIPCManager = NonosIPCManager::new();

/// Get the global IPC manager
#[inline]
pub fn get_ipc_manager() -> &'static NonosIPCManager {
    &NONOS_IPC_MANAGER
}
