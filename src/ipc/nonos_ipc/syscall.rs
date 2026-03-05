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

//! Syscall-level IPC API.

extern crate alloc;

use alloc::vec::Vec;

use super::error::{IpcError, IpcManagerError};
use super::manager::NONOS_IPC_MANAGER;
use super::types::{NonosChannelType, NonosIPCMessage, NonosMessageType};

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

/// Send a message via syscall interface
pub fn send_message(channel_id: u32, data: &[u8]) -> Result<(), IpcError> {
    let token = crate::syscall::capabilities::current_caps_or_default();
    if !token.can_ipc() {
        return Err(IpcError::PermissionDenied);
    }

    let pid = crate::process::current_pid().unwrap_or(0) as u64;

    NONOS_IPC_MANAGER
        .send_message(
            pid,
            channel_id as u64,
            pid, // self-send for channel-based routing
            NonosMessageType::Data,
            data.to_vec(),
        )
        .map(|_| ())
        .map_err(IpcError::from)
}

/// Receive a message via syscall interface (non-blocking)
pub fn recv_message(_channel_id: u32, buffer: &mut [u8]) -> Result<usize, IpcError> {
    let token = crate::syscall::capabilities::current_caps_or_default();
    if !token.can_ipc() {
        return Err(IpcError::PermissionDenied);
    }

    let pid = crate::process::current_pid().unwrap_or(0) as u64;

    // Check all channels this process is part of
    for channel_id in NONOS_IPC_MANAGER.get_process_channels(pid) {
        if let Ok(Some(msg)) = NONOS_IPC_MANAGER.receive_message(pid, channel_id) {
            let len = msg.payload.len().min(buffer.len());
            buffer[..len].copy_from_slice(&msg.payload[..len]);
            return Ok(len);
        }
    }

    Err(IpcError::WouldBlock)
}

/// Create a channel via syscall interface
pub fn create_channel(_flags: u32) -> Result<u32, IpcError> {
    let token = crate::syscall::capabilities::current_caps_or_default();
    if !token.can_ipc() {
        return Err(IpcError::PermissionDenied);
    }

    let pid = crate::process::current_pid().unwrap_or(0) as u64;

    NONOS_IPC_MANAGER
        .create_channel(pid, NonosChannelType::MessagePassing, alloc::vec![pid])
        .map(|id| id as u32)
        .map_err(IpcError::from)
}

/// Destroy a channel via syscall interface
pub fn destroy_channel(channel_id: u32) -> Result<(), IpcError> {
    let token = crate::syscall::capabilities::current_caps_or_default();
    if !token.can_ipc() {
        return Err(IpcError::PermissionDenied);
    }

    let pid = crate::process::current_pid().unwrap_or(0) as u64;

    NONOS_IPC_MANAGER
        .destroy_channel(pid, channel_id as u64)
        .map_err(IpcError::from)
}
