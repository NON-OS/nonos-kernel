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

//! IPC channel and queue types.

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use spin::Mutex;

use super::types::{NonosChannelType, NonosIPCMessage};

/// Maximum queue capacity
pub(super) const MAX_QUEUE_CAPACITY: usize = 65536;

/// Bounded message queue for a channel
#[derive(Debug, Clone)]
pub(super) struct ChannelQueue {
    queue: VecDeque<NonosIPCMessage>,
    capacity: usize,
}

impl ChannelQueue {
    pub(super) fn new(capacity: usize) -> Self {
        let cap = capacity.min(MAX_QUEUE_CAPACITY);
        Self {
            queue: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.queue.len()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[inline]
    pub(super) fn is_full(&self) -> bool {
        self.queue.len() >= self.capacity
    }

    pub(super) fn push(&mut self, msg: NonosIPCMessage) -> Result<(), usize> {
        if self.is_full() {
            Err(self.capacity)
        } else {
            self.queue.push_back(msg);
            Ok(())
        }
    }

    pub(super) fn pop_for(&mut self, receiver_id: u64) -> Option<NonosIPCMessage> {
        if let Some(pos) = self.queue.iter().position(|m| m.recipient_id == receiver_id) {
            self.queue.remove(pos)
        } else {
            None
        }
    }

    pub(super) fn peek_for(&self, receiver_id: u64) -> Option<&NonosIPCMessage> {
        self.queue.iter().find(|m| m.recipient_id == receiver_id)
    }

    pub(super) fn count_for(&self, receiver_id: u64) -> usize {
        self.queue.iter().filter(|m| m.recipient_id == receiver_id).count()
    }
}

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
    pub(super) queue: Mutex<ChannelQueue>,
}

impl NonosIPCChannel {
    pub(super) fn new(
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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::NonosMessageType;

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
                payload: alloc::vec![],
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
            payload: alloc::vec![],
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
                payload: alloc::vec![],
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
}
