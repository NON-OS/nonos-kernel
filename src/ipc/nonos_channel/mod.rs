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

//! IPC Channel and Message Bus
//!
//! Provides the core IPC message passing infrastructure:
//! - `IpcMessage` - Message with integrity checksum
//! - `IpcChannel` - Handle to a registered route
//! - `IpcBus` - Global message bus with channel registry
//!
//! # Architecture
//!
//! The IPC bus maintains a registry of channels (routes between modules).
//! Messages are enqueued on the bus and later dequeued for delivery.
//! Each channel is identified by a BLAKE3-derived key for fast lookup.
//!
//! # RAM-Only Design
//!
//! All channel state is held in memory. No persistence layer exists.
//! On system reset, all channels and queued messages are lost.
//!
//! # Example
//!
//! ```ignore
//! use nonos_kernel::ipc::nonos_channel::{IPC_BUS, IpcMessage};
//!
//! // Open a channel
//! IPC_BUS.open_channel("sender", "receiver", &token)?;
//!
//! // Find and send on channel
//! if let Some(channel) = IPC_BUS.find_channel("sender", "receiver") {
//!     let msg = IpcMessage::new("sender", "receiver", &data)?;
//!     channel.send(msg)?;
//! }
//! ```

mod bus;
mod channel;
mod error;
mod hash;
mod message;
mod stats;

// Re-export public API
pub use bus::{IpcBus, IPC_BUS, DEFAULT_MAX_QUEUE, DEFAULT_MSG_TIMEOUT_MS};
pub use channel::IpcChannel;
pub use error::ChannelError;
pub use hash::{compute_channel_key, compute_checksum};
pub use message::{IpcMessage, MAX_MESSAGE_SIZE};
pub use stats::BusStatsSnapshot;
