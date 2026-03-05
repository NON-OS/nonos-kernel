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

//! Frame header and parsing.

extern crate alloc;

use alloc::vec::Vec;

use super::error::TransportError;

/// Frame magic number ("STRM" in little-endian)
pub const FRAME_MAGIC: u32 = 0x5354_524D;

/// Current frame format version
pub const FRAME_VERSION: u16 = 1;

/// End of stream flag
pub const FLAG_EOF: u8 = 0x01;

/// Frame header size in bytes
pub const FRAME_HEADER_SIZE: usize = 23; // 4 + 2 + 8 + 4 + 4 + 1

/// Parsed frame header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Magic number (must be FRAME_MAGIC)
    pub magic: u32,
    /// Frame format version
    pub version: u16,
    /// Stream identifier
    pub stream_id: u64,
    /// Sequence number (0-indexed)
    pub seq: u32,
    /// Total number of frames
    pub total: u32,
    /// Flags (FLAG_EOF etc)
    pub flags: u8,
}

impl FrameHeader {
    /// Check if this is the final frame
    pub fn is_eof(&self) -> bool {
        self.flags & FLAG_EOF != 0
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_SIZE] {
        let mut buf = [0u8; FRAME_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..14].copy_from_slice(&self.stream_id.to_le_bytes());
        buf[14..18].copy_from_slice(&self.seq.to_le_bytes());
        buf[18..22].copy_from_slice(&self.total.to_le_bytes());
        buf[22] = self.flags;
        buf
    }

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, TransportError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(TransportError::FrameTooShort {
                size: data.len(),
                minimum: FRAME_HEADER_SIZE,
            });
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != FRAME_MAGIC {
            return Err(TransportError::InvalidMagic {
                expected: FRAME_MAGIC,
                found: magic,
            });
        }

        let version = u16::from_le_bytes([data[4], data[5]]);
        if version != FRAME_VERSION {
            return Err(TransportError::UnsupportedVersion { version });
        }

        let stream_id = u64::from_le_bytes([
            data[6], data[7], data[8], data[9],
            data[10], data[11], data[12], data[13],
        ]);
        let seq = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
        let total = u32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        let flags = data[22];

        // Validate sequence
        if total > 0 && seq >= total {
            return Err(TransportError::SequenceOutOfRange { seq, total });
        }

        Ok(Self {
            magic,
            version,
            stream_id,
            seq,
            total,
            flags,
        })
    }
}

/// Build a complete frame with header and payload
pub(super) fn build_frame(header: &FrameHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse a frame into header and payload
pub fn parse_frame(data: &[u8]) -> Result<(FrameHeader, &[u8]), TransportError> {
    let header = FrameHeader::from_bytes(data)?;
    let payload = &data[FRAME_HEADER_SIZE..];
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_roundtrip() {
        let header = FrameHeader {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            stream_id: 0x1234_5678_9ABC_DEF0,
            seq: 42,
            total: 100,
            flags: FLAG_EOF,
        };

        let bytes = header.to_bytes();
        let parsed = FrameHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, header.magic);
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.stream_id, header.stream_id);
        assert_eq!(parsed.seq, header.seq);
        assert_eq!(parsed.total, header.total);
        assert_eq!(parsed.flags, header.flags);
    }

    #[test]
    fn test_frame_header_invalid_magic() {
        let mut bytes = [0u8; FRAME_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let result = FrameHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(TransportError::InvalidMagic { .. })));
    }

    #[test]
    fn test_frame_header_invalid_version() {
        let mut bytes = [0u8; FRAME_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());

        let result = FrameHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(TransportError::UnsupportedVersion { version: 99 })));
    }

    #[test]
    fn test_frame_header_too_short() {
        let bytes = [0u8; 10];
        let result = FrameHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(TransportError::FrameTooShort { .. })));
    }

    #[test]
    fn test_frame_header_seq_out_of_range() {
        let header = FrameHeader {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            stream_id: 1,
            seq: 10, // >= total
            total: 5,
            flags: 0,
        };
        let bytes = header.to_bytes();
        let result = FrameHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(TransportError::SequenceOutOfRange { seq: 10, total: 5 })));
    }

    #[test]
    fn test_parse_frame() {
        let header = FrameHeader {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            stream_id: 123,
            seq: 0,
            total: 1,
            flags: FLAG_EOF,
        };
        let payload = b"hello world";
        let frame = build_frame(&header, payload);

        let (parsed_header, parsed_payload) = parse_frame(&frame).unwrap();
        assert_eq!(parsed_header.stream_id, 123);
        assert_eq!(parsed_payload, payload);
    }
}
