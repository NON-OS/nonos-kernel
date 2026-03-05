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

//! NONOS IPC Transport Layer
//!
//! Provides framed stream transport for large payloads over the IPC message bus.
//! Payloads are split into MTU-sized frames with sequence numbers for reassembly.
//!
//! # Frame Format
//!
//! ```text
//! +--------+--------+----------+-----+-------+-------+---------+
//! | magic  | version| stream_id| seq | total | flags | payload |
//! | 4 bytes| 2 bytes| 8 bytes  | 4B  | 4B    | 1B    | variable|
//! +--------+--------+----------+-----+-------+-------+---------+
//!
//! magic: 0x5354524D ("STRM")
//! version: 1
//! stream_id: unique stream identifier
//! seq: sequence number (0-indexed)
//! total: total number of frames
//! flags: FLAG_EOF (0x01) marks final frame
//! ```
//!
//! # Usage
//!
//! ```ignore
//! // Create a stream
//! let stream = IpcStream::new("sender", "receiver")
//!     .with_mtu(4096)
//!     .with_security(SecurityLevel::Signed);
//!
//! // Send large payload
//! send_stream_payload(&stream, &large_data, |env| {
//!     ipc_bus.send(env)
//! })?;
//!
//! // Receive and reassemble
//! let mut assembler = StreamAssembler::new();
//! for frame_data in incoming_frames {
//!     if let Some(complete) = assembler.add_frame(&frame_data)? {
//!         process_payload(&complete);
//!     }
//! }
//! ```

mod assembler;
mod error;
mod frame;
mod stream;

// Re-export public API
pub use assembler::{get_assembler, StreamAssembler};
pub use error::TransportError;
pub use frame::{parse_frame, FrameHeader, FRAME_HEADER_SIZE, FRAME_MAGIC, FRAME_VERSION, FLAG_EOF};
pub use stream::{send_stream_payload, IpcStream, DEFAULT_MTU, MAX_MTU, MAX_PAYLOAD_SIZE, MIN_MTU};
