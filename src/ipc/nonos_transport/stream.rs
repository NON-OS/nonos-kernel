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

//! Stream descriptor and sending.

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ipc::nonos_message::{IpcEnvelope, MessageType, SecurityLevel};
use super::error::TransportError;
use super::frame::{build_frame, FrameHeader, FLAG_EOF, FRAME_HEADER_SIZE, FRAME_MAGIC, FRAME_VERSION};

/// Minimum MTU size
pub const MIN_MTU: usize = 256;

/// Maximum MTU size
pub const MAX_MTU: usize = 64 * 1024;

/// Default MTU (conservative for IPC messages)
pub const DEFAULT_MTU: usize = 4096 - FRAME_HEADER_SIZE;

/// Maximum payload size (prevent memory exhaustion)
pub const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024; // 64 MB

/// A stream descriptor for framed large-payload transport
#[derive(Debug, Clone)]
pub struct IpcStream {
    /// Source module/process
    pub from: String,
    /// Destination module/process
    pub to: String,
    /// Unique stream identifier
    pub stream_id: u64,
    /// Maximum payload bytes per frame (not counting header)
    pub mtu: usize,
    /// Security level for frames
    pub sec_level: SecurityLevel,
}

impl IpcStream {
    /// Create a new stream with default settings
    pub fn new(from: &str, to: &str) -> Self {
        Self {
            from: String::from(from),
            to: String::from(to),
            stream_id: next_stream_id(),
            mtu: DEFAULT_MTU,
            sec_level: SecurityLevel::None,
        }
    }

    /// Set custom MTU (clamped to valid range)
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu.clamp(MIN_MTU, MAX_MTU);
        self
    }

    /// Set security level for frames
    pub fn with_security(mut self, level: SecurityLevel) -> Self {
        self.sec_level = level;
        self
    }

    /// Calculate number of frames needed for a payload
    pub fn frames_needed(&self, payload_len: usize) -> usize {
        if payload_len == 0 {
            1 // EOF frame
        } else {
            (payload_len + self.mtu - 1) / self.mtu
        }
    }
}

/// Generate a unique stream ID
pub(super) fn next_stream_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let salt = crate::time::timestamp_millis();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix timestamp and counter for uniqueness
    salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ counter
}

/// Send a payload via framed stream.
///
/// The tx function is responsible for policy/capability checks at the envelope layer.
/// Large payloads are automatically split into MTU-sized frames.
///
/// # Arguments
/// * `stream` - Stream descriptor with source, destination, and MTU
/// * `payload` - Data to send (can be empty for EOF-only)
/// * `tx` - Callback to transmit each envelope
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(TransportError)` on failure
pub fn send_stream_payload<F>(
    stream: &IpcStream,
    payload: &[u8],
    mut tx: F,
) -> Result<(), TransportError>
where
    F: FnMut(IpcEnvelope) -> Result<(), &'static str>,
{
    // Validate payload size
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(TransportError::PayloadTooLarge {
            size: payload.len(),
            maximum: MAX_PAYLOAD_SIZE,
        });
    }

    // Handle empty payload (EOF frame only)
    if payload.is_empty() {
        let header = FrameHeader {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            stream_id: stream.stream_id,
            seq: 0,
            total: 0,
            flags: FLAG_EOF,
        };
        let env = IpcEnvelope {
            from: stream.from.clone(),
            to: stream.to.clone(),
            message_type: MessageType::Data,
            data: build_frame(&header, &[]),
            timestamp: crate::time::timestamp_millis(),
            session_id: None,
            sec_level: stream.sec_level,
        };
        return tx(env).map_err(|_| TransportError::TransmitFailed);
    }

    let total = stream.frames_needed(payload.len());

    for seq in 0..total {
        let start = seq * stream.mtu;
        let end = (start + stream.mtu).min(payload.len());
        let chunk = &payload[start..end];

        let header = FrameHeader {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            stream_id: stream.stream_id,
            seq: seq as u32,
            total: total as u32,
            flags: if seq + 1 == total { FLAG_EOF } else { 0 },
        };

        let env = IpcEnvelope {
            from: stream.from.clone(),
            to: stream.to.clone(),
            message_type: MessageType::Data,
            data: build_frame(&header, chunk),
            timestamp: crate::time::timestamp_millis(),
            session_id: None,
            sec_level: stream.sec_level,
        };

        tx(env).map_err(|_| TransportError::TransmitFailed)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_mtu_clamping() {
        let stream = IpcStream::new("a", "b").with_mtu(10);
        assert_eq!(stream.mtu, MIN_MTU);

        let stream = IpcStream::new("a", "b").with_mtu(1_000_000);
        assert_eq!(stream.mtu, MAX_MTU);

        let stream = IpcStream::new("a", "b").with_mtu(1000);
        assert_eq!(stream.mtu, 1000);
    }

    #[test]
    fn test_frames_needed() {
        let stream = IpcStream::new("a", "b").with_mtu(100);
        assert_eq!(stream.frames_needed(0), 1); // EOF frame
        assert_eq!(stream.frames_needed(50), 1);
        assert_eq!(stream.frames_needed(100), 1);
        assert_eq!(stream.frames_needed(101), 2);
        assert_eq!(stream.frames_needed(250), 3);
    }

    #[test]
    fn test_stream_id_uniqueness() {
        let id1 = next_stream_id();
        let id2 = next_stream_id();
        let id3 = next_stream_id();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }
}
