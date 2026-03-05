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

//! Transport layer error types.

/// Transport layer errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Frame magic number invalid
    InvalidMagic { expected: u32, found: u32 },
    /// Unsupported frame version
    UnsupportedVersion { version: u16 },
    /// Frame too short to contain header
    FrameTooShort { size: usize, minimum: usize },
    /// Sequence number out of range
    SequenceOutOfRange { seq: u32, total: u32 },
    /// Duplicate frame received
    DuplicateFrame { stream_id: u64, seq: u32 },
    /// Stream not found in assembler
    StreamNotFound { stream_id: u64 },
    /// MTU too small
    MtuTooSmall { mtu: usize, minimum: usize },
    /// MTU too large
    MtuTooLarge { mtu: usize, maximum: usize },
    /// Payload exceeds maximum size
    PayloadTooLarge { size: usize, maximum: usize },
    /// Transmission callback failed
    TransmitFailed,
    /// Assembly timeout
    AssemblyTimeout { stream_id: u64 },
    /// Stream limit exceeded
    TooManyStreams { count: usize, limit: usize },
}

impl TransportError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMagic { .. } => "Invalid frame magic number",
            Self::UnsupportedVersion { .. } => "Unsupported frame version",
            Self::FrameTooShort { .. } => "Frame too short for header",
            Self::SequenceOutOfRange { .. } => "Sequence number out of range",
            Self::DuplicateFrame { .. } => "Duplicate frame received",
            Self::StreamNotFound { .. } => "Stream not found",
            Self::MtuTooSmall { .. } => "MTU too small",
            Self::MtuTooLarge { .. } => "MTU too large",
            Self::PayloadTooLarge { .. } => "Payload exceeds maximum size",
            Self::TransmitFailed => "Transmission failed",
            Self::AssemblyTimeout { .. } => "Assembly timeout",
            Self::TooManyStreams { .. } => "Too many concurrent streams",
        }
    }
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic { expected, found } => {
                write!(f, "Invalid frame magic: expected 0x{:08X}, found 0x{:08X}", expected, found)
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "Unsupported frame version: {}", version)
            }
            Self::FrameTooShort { size, minimum } => {
                write!(f, "Frame too short: {} bytes, minimum {} bytes", size, minimum)
            }
            Self::SequenceOutOfRange { seq, total } => {
                write!(f, "Sequence {} out of range (total: {})", seq, total)
            }
            Self::DuplicateFrame { stream_id, seq } => {
                write!(f, "Duplicate frame: stream 0x{:016X} seq {}", stream_id, seq)
            }
            Self::StreamNotFound { stream_id } => {
                write!(f, "Stream not found: 0x{:016X}", stream_id)
            }
            Self::MtuTooSmall { mtu, minimum } => {
                write!(f, "MTU {} too small, minimum {}", mtu, minimum)
            }
            Self::MtuTooLarge { mtu, maximum } => {
                write!(f, "MTU {} too large, maximum {}", mtu, maximum)
            }
            Self::PayloadTooLarge { size, maximum } => {
                write!(f, "Payload {} bytes exceeds maximum {} bytes", size, maximum)
            }
            Self::TransmitFailed => write!(f, "Transmission failed"),
            Self::AssemblyTimeout { stream_id } => {
                write!(f, "Assembly timeout for stream 0x{:016X}", stream_id)
            }
            Self::TooManyStreams { count, limit } => {
                write!(f, "Too many streams: {} exceeds limit {}", count, limit)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame::FRAME_MAGIC;

    #[test]
    fn test_error_display() {
        let err = TransportError::InvalidMagic {
            expected: FRAME_MAGIC,
            found: 0xDEADBEEF,
        };
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("5354524D"));
        assert!(msg.contains("DEADBEEF"));

        let err = TransportError::SequenceOutOfRange { seq: 5, total: 3 };
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }
}
