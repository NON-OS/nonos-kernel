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

use super::error::{IpcError, IpcManagerError};
use super::manager::NONOS_IPC_MANAGER;
use super::types::{NonosChannelType, NonosIPCMessage, NonosMessageType};
use alloc::vec::Vec;

pub fn create_ipc_channel(
    _creator_id: u64,
    channel_type: NonosChannelType,
    mut participants: Vec<u64>,
) -> Result<u64, IpcManagerError> {
    let actual_creator = crate::process::current_pid().unwrap_or(0) as u64;
    if !participants.contains(&actual_creator) {
        participants.push(actual_creator);
    }
    NONOS_IPC_MANAGER.create_channel(actual_creator, channel_type, participants)
}

pub fn send_ipc_message(
    _sender_id: u64,
    channel_id: u64,
    recipient_id: u64,
    message_type: NonosMessageType,
    payload: Vec<u8>,
) -> Result<u64, IpcManagerError> {
    let actual_sender = crate::process::current_pid().unwrap_or(0) as u64;
    NONOS_IPC_MANAGER.send_message(actual_sender, channel_id, recipient_id, message_type, payload)
}

pub fn receive_ipc_message(
    _receiver_id: u64,
    channel_id: u64,
) -> Result<Option<NonosIPCMessage>, IpcManagerError> {
    let actual_receiver = crate::process::current_pid().unwrap_or(0) as u64;
    NONOS_IPC_MANAGER.receive_message(actual_receiver, channel_id)
}

pub fn destroy_ipc_channel(_destroyer_id: u64, channel_id: u64) -> Result<(), IpcManagerError> {
    let actual_destroyer = crate::process::current_pid().unwrap_or(0) as u64;
    NONOS_IPC_MANAGER.destroy_channel(actual_destroyer, channel_id)
}

fn can_do_ipc() -> bool {
    match crate::process::current_pid() {
        None => true,
        Some(pid) if pid <= 16 => true,
        Some(_) => crate::syscall::capabilities::current_caps_or_default().can_ipc(),
    }
}

pub fn send_message(channel_id: u32, data: &[u8]) -> Result<(), IpcError> {
    if !can_do_ipc() {
        return Err(IpcError::PermissionDenied);
    }
    let pid = crate::process::current_pid().unwrap_or(0) as u64;
    NONOS_IPC_MANAGER
        .send_message(pid, channel_id as u64, pid, NonosMessageType::Data, data.to_vec())
        .map(|_| ())
        .map_err(IpcError::from)
}

pub fn recv_message(_channel_id: u32, buffer: &mut [u8]) -> Result<usize, IpcError> {
    if !can_do_ipc() {
        return Err(IpcError::PermissionDenied);
    }
    let pid = crate::process::current_pid().unwrap_or(0) as u64;
    for channel_id in NONOS_IPC_MANAGER.get_process_channels(pid) {
        if let Ok(Some(msg)) = NONOS_IPC_MANAGER.receive_message(pid, channel_id) {
            let len = msg.payload.len().min(buffer.len());
            buffer[..len].copy_from_slice(&msg.payload[..len]);
            return Ok(len);
        }
    }
    Err(IpcError::WouldBlock)
}

pub fn create_channel(_flags: u32) -> Result<u32, IpcError> {
    if !can_do_ipc() {
        return Err(IpcError::PermissionDenied);
    }
    let pid = crate::process::current_pid().unwrap_or(0) as u64;
    NONOS_IPC_MANAGER
        .create_channel(pid, NonosChannelType::MessagePassing, alloc::vec![pid])
        .map(|id| id as u32)
        .map_err(IpcError::from)
}

pub fn destroy_channel(channel_id: u32) -> Result<(), IpcError> {
    if !can_do_ipc() {
        return Err(IpcError::PermissionDenied);
    }
    let pid = crate::process::current_pid().unwrap_or(0) as u64;
    NONOS_IPC_MANAGER.destroy_channel(pid, channel_id as u64).map_err(IpcError::from)
}
