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

extern crate alloc;
use super::super::error::IpcManagerError;
use super::super::types::{NonosIPCMessage, NonosMessageType};
use super::core::NonosIPCManager;
use super::types::MAX_PAYLOAD_SIZE;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl NonosIPCManager {
    pub fn send_message(
        &self,
        sender_id: u64,
        channel_id: u64,
        recipient_id: u64,
        message_type: NonosMessageType,
        payload: Vec<u8>,
    ) -> Result<u64, IpcManagerError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(IpcManagerError::PayloadTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        let msg_id = self.next_message_id.fetch_add(1, Ordering::Relaxed);
        let now = crate::time::timestamp_millis();
        let mut ch_map = self.channels.write();
        let channel =
            ch_map.get_mut(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;
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
        let result = match channel.queue.lock().push(msg) {
            Ok(()) => {
                self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                Ok(msg_id)
            }
            Err(capacity) => {
                self.stats.messages_dropped.fetch_add(1, Ordering::Relaxed);
                Err(IpcManagerError::QueueFull { channel_id, capacity })
            }
        };
        drop(ch_map);
        result
    }

    pub fn receive_message(
        &self,
        receiver_id: u64,
        channel_id: u64,
    ) -> Result<Option<NonosIPCMessage>, IpcManagerError> {
        let mut ch_map = self.channels.write();
        let channel =
            ch_map.get_mut(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;
        if !channel.has_participant(receiver_id) {
            return Err(IpcManagerError::ReceiverNotAuthorized { receiver_id, channel_id });
        }
        let result = channel.queue.lock().pop_for(receiver_id);
        if result.is_some() {
            self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    pub fn peek_message(
        &self,
        receiver_id: u64,
        channel_id: u64,
    ) -> Result<Option<NonosIPCMessage>, IpcManagerError> {
        let ch_map = self.channels.read();
        let channel =
            ch_map.get(&channel_id).ok_or(IpcManagerError::ChannelNotFound { channel_id })?;
        if !channel.has_participant(receiver_id) {
            return Err(IpcManagerError::ReceiverNotAuthorized { receiver_id, channel_id });
        }
        let result = channel.queue.lock().peek_for(receiver_id).cloned();
        drop(ch_map);
        Ok(result)
    }
}
