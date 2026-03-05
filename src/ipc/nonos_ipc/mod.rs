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

//! PID-Based IPC Manager
//!
//! Process-oriented inter-process communication with:
//! - Multiple channel types (SharedMemory, MessagePassing, Signal, Pipe, Socket)
//! - Participant-based access control
//! - Bounded message queues per channel
//! - Priority-based message handling
//!
//! # Architecture
//!
//! ```text
//! Process A ──┐                    ┌── Process C
//!             │    ┌──────────┐    │
//!             ├───►│ Channel  │◄───┤
//!             │    │  Queue   │    │
//! Process B ──┘    └──────────┘    └── Process D
//! ```
//!
//! # Usage
//!
//! ```ignore
//! // Create a channel between processes
//! let channel_id = create_ipc_channel(
//!     pid_a,
//!     NonosChannelType::MessagePassing,
//!     vec![pid_a, pid_b],
//! )?;
//!
//! // Send a message
//! let msg_id = send_ipc_message(
//!     pid_a,
//!     channel_id,
//!     pid_b,
//!     NonosMessageType::Data,
//!     payload,
//! )?;
//!
//! // Receive messages
//! if let Some(msg) = receive_ipc_message(pid_b, channel_id)? {
//!     process_message(msg);
//! }
//! ```

mod channel;
mod error;
mod manager;
mod syscall;
mod types;

// Re-export public API
pub use channel::NonosIPCChannel;
pub use error::{IpcError, IpcManagerError};
pub use manager::{get_ipc_manager, ManagerStatsSnapshot, NonosIPCManager, NONOS_IPC_MANAGER};
pub use syscall::{
    create_channel, create_ipc_channel, destroy_channel, destroy_ipc_channel,
    receive_ipc_message, recv_message, send_ipc_message, send_message,
};
pub use types::{NonosChannelType, NonosIPCMessage, NonosMessageType};
