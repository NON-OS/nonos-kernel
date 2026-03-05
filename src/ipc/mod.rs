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

pub mod api;
pub mod daemon;
pub mod nonos_channel;
pub mod nonos_inbox;
pub mod nonos_ipc;
pub mod nonos_message;
pub mod nonos_policy;
pub mod nonos_transport;
pub mod pipe;

pub mod eventfd {
    pub use crate::syscall::extended::eventfd::*;
}

pub mod signalfd {
    pub use crate::syscall::extended::signalfd::*;
}

pub use nonos_channel as channel;
pub use nonos_message as message;
pub use nonos_policy as policy;
pub use nonos_transport as transport;

pub use api::{
    get_bus_stats, get_policy_stats, init, init_ipc, list_routes, open_secure_channel,
    send_envelope,
};
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
