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
//! NØNOS IPC Subsystem
//!
//! RAM-only inter-process communication infrastructure.

pub mod daemon;
pub mod nonos_channel;
pub mod nonos_inbox;
pub mod nonos_ipc;
pub mod nonos_message;
pub mod nonos_policy;
pub mod nonos_transport;

// Backward-compatible aliases
pub use nonos_channel as channel;
pub use nonos_message as message;
pub use nonos_policy as policy;
pub use nonos_transport as transport;

// Re-export primary types
pub use daemon::{process_message_queue, request_shutdown, run_daemon};
pub use nonos_channel::{IpcChannel, IpcMessage, IPC_BUS};
pub use nonos_inbox::{InboxError, InboxStatsSnapshot};
pub use nonos_ipc::{
    create_channel, create_ipc_channel, destroy_channel, destroy_ipc_channel, get_ipc_manager,
    receive_ipc_message, recv_message, send_ipc_message, send_message, IpcError,
    IpcManagerError, NonosChannelType, NonosIPCChannel, NonosIPCMessage, NonosMessageType,
    NONOS_IPC_MANAGER,
};
pub use nonos_message::{IpcEnvelope, MessageType, SecurityLevel};
pub use nonos_policy::{get_policy, IpcCapability, ModulePolicy, PolicyViolation, ACTIVE_POLICY};
pub use nonos_transport::{
    get_assembler, parse_frame, FrameHeader, IpcStream, StreamAssembler, TransportError,
};

use crate::syscall::capabilities::CapabilityToken;

/// Initialize the IPC subsystem.
///
/// Call once during kernel boot. Initializes:
/// - Default module policies
/// - Statistics tracking
pub fn init() {
    nonos_policy::init_default_policies();
}

/// Alias for `init()` (backward compatibility).
#[inline]
pub fn init_ipc() {
    init();
}

/// Send a policy-validated envelope through the message bus.
///
/// Validates against active policy before routing to destination.
pub fn send_envelope(envelope: IpcEnvelope, token: &CapabilityToken) -> Result<(), &'static str> {
    if !get_policy().allow_message(&envelope, token) {
        return Err("IPC policy violation: send denied");
    }

    if let Some(channel) = IPC_BUS.find_channel(&envelope.from, &envelope.to) {
        channel.send(IpcMessage::new(&envelope.from, &envelope.to, &envelope.data)?)?;
        Ok(())
    } else {
        Err("No IPC channel found")
    }
}

/// Open a policy-validated channel between modules.
pub fn open_secure_channel(
    from: &str,
    to: &str,
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    if !get_policy().allow_channel(from, to, token) {
        return Err("IPC policy violation: open_channel denied");
    }
    nonos_inbox::register_inbox(to);
    IPC_BUS.open_channel(from, to, token)
}

/// List active module-to-module routes.
#[inline]
pub fn list_routes() -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)> {
    IPC_BUS.list_routes()
}

/// Get IPC bus statistics.
#[inline]
pub fn get_bus_stats() -> nonos_channel::BusStatsSnapshot {
    IPC_BUS.get_stats()
}

/// Get policy statistics.
#[inline]
pub fn get_policy_stats() -> nonos_policy::PolicyStatsSnapshot {
    get_policy().get_stats()
}
