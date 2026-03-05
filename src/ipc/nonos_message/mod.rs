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

//! IPC Message Types
//!
//! Core message structures for inter-process communication:
//! - `IpcEnvelope` - Message container with routing and security metadata
//! - `MessageType` - Message classification (data, control, error, etc.)
//! - `SecurityLevel` - Message security/signing requirements
//!
//! # Example
//!
//! ```ignore
//! let envelope = IpcEnvelope::builder("sender", "receiver")
//!     .message_type(MessageType::Data)
//!     .data(payload)
//!     .security_level(SecurityLevel::Signed)
//!     .build();
//! ```

mod builder;
mod envelope;
mod types;

// Re-export public API
pub use builder::EnvelopeBuilder;
pub use envelope::{IpcEnvelope, MAX_PAYLOAD_SIZE};
pub use types::{MessageError, MessageType, SecurityLevel};
