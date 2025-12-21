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
//! NØNOS IPC Transport Layer
//!
//! Provides framed stream transport for large payloads over the IPC message bus.
//! Payloads are split into MTU-sized frames with sequence numbers for reassembly.
//!
//! # Frame Format
//! +--------+--------+----------+-----+-------+-------+---------+
//! | magic  | version| stream_id| seq | total | flags | payload |
//! | 4 bytes| 2 bytes| 8 bytes  | 4B  | 4B    | 1B    | variable|
//! +--------+--------+----------+-----+-------+-------+---------+
//! magic: 0x5354524D ("STRM")
//! version: 1
//! stream_id: unique stream identifier
//! seq: sequence number (0-indexed)
//! total: total number of frames
//! flags: FLAG_EOF (0x01) marks final frame

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::nonos_message::{IpcEnvelope, MessageType, SecurityLevel};

// ============================================================================
// Error Types
// ============================================================================

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

// ============================================================================
// Constants
// ============================================================================

/// Frame magic number ("STRM" in little-endian)
const FRAME_MAGIC: u32 = 0x5354_524D;

/// Current frame format version
const FRAME_VERSION: u16 = 1;

/// End of stream flag
const FLAG_EOF: u8 = 0x01;

/// Frame header size in bytes
const FRAME_HEADER_SIZE: usize = 23; // 4 + 2 + 8 + 4 + 4 + 1

/// Minimum MTU size
const MIN_MTU: usize = 256;

/// Maximum MTU size
const MAX_MTU: usize = 64 * 1024;

/// Default MTU (conservative for IPC messages)
const DEFAULT_MTU: usize = 4096 - FRAME_HEADER_SIZE;

/// Maximum payload size (prevent memory exhaustion)
const MAX_PAYLOAD_SIZE: usize = 64 * 1024 * 1024; // 64 MB

/// Maximum concurrent streams per assembler
const MAX_CONCURRENT_STREAMS: usize = 256;

/// Stream assembly timeout in milliseconds
const STREAM_TIMEOUT_MS: u64 = 30_000;

// ============================================================================
// Stream Descriptor
// ============================================================================

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

// ============================================================================
// Frame Header
// ============================================================================

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

// ============================================================================
// Frame Building
// ============================================================================

/// Build a complete frame with header and payload
fn build_frame(header: &FrameHeader, payload: &[u8]) -> Vec<u8> {
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

// ============================================================================
// Stream Sending
// ============================================================================

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

// ============================================================================
// Stream Reassembly
// ============================================================================

/// In-progress stream assembly state
struct StreamAssemblyState {
    /// Expected total frames
    total: u32,
    /// Received frames (indexed by sequence number)
    frames: BTreeMap<u32, Vec<u8>>,
    /// Timestamp when stream started (for timeout)
    started_ms: u64,
    /// From address for validation
    from: String,
}

/// Stream assembler for receiving and reassembling framed payloads
pub struct StreamAssembler {
    /// Active streams being assembled
    streams: Mutex<BTreeMap<u64, StreamAssemblyState>>,
    /// Statistics
    stats: AssemblerStats,
}

/// Assembler statistics
struct AssemblerStats {
    frames_received: AtomicU64,
    streams_completed: AtomicU64,
    streams_timed_out: AtomicU64,
    bytes_assembled: AtomicU64,
}

impl StreamAssembler {
    /// Create a new stream assembler
    pub const fn new() -> Self {
        Self {
            streams: Mutex::new(BTreeMap::new()),
            stats: AssemblerStats {
                frames_received: AtomicU64::new(0),
                streams_completed: AtomicU64::new(0),
                streams_timed_out: AtomicU64::new(0),
                bytes_assembled: AtomicU64::new(0),
            },
        }
    }

    /// Add a frame and return completed payload if stream is complete
    ///
    /// # Arguments
    /// * `data` - Raw frame data including header
    /// * `from` - Source address for validation
    ///
    /// # Returns
    /// * `Ok(Some(payload))` - Stream complete, payload reassembled
    /// * `Ok(None)` - Frame added, waiting for more frames
    /// * `Err(TransportError)` - Parse or validation error
    pub fn add_frame(&self, data: &[u8], from: &str) -> Result<Option<Vec<u8>>, TransportError> {
        let (header, payload) = parse_frame(data)?;

        self.stats.frames_received.fetch_add(1, Ordering::Relaxed);

        // Handle empty EOF (zero-length stream)
        if header.total == 0 && header.is_eof() {
            self.stats.streams_completed.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(Vec::new()));
        }

        let mut streams = self.streams.lock();

        // Check stream limit
        if !streams.contains_key(&header.stream_id) && streams.len() >= MAX_CONCURRENT_STREAMS {
            return Err(TransportError::TooManyStreams {
                count: streams.len(),
                limit: MAX_CONCURRENT_STREAMS,
            });
        }

        // Get or create stream state
        let state = streams.entry(header.stream_id).or_insert_with(|| {
            StreamAssemblyState {
                total: header.total,
                frames: BTreeMap::new(),
                started_ms: crate::time::timestamp_millis(),
                from: String::from(from),
            }
        });

        // Validate source
        if state.from != from {
            // Different source trying to inject frames
            return Err(TransportError::StreamNotFound {
                stream_id: header.stream_id,
            });
        }

        // Check for duplicate
        if state.frames.contains_key(&header.seq) {
            return Err(TransportError::DuplicateFrame {
                stream_id: header.stream_id,
                seq: header.seq,
            });
        }

        // Store frame payload
        state.frames.insert(header.seq, payload.to_vec());

        // Check if complete
        if state.frames.len() == header.total as usize {
            // Reassemble payload
            let mut complete = Vec::new();
            for seq in 0..header.total {
                if let Some(chunk) = state.frames.get(&seq) {
                    complete.extend_from_slice(chunk);
                }
            }

            self.stats.streams_completed.fetch_add(1, Ordering::Relaxed);
            self.stats.bytes_assembled.fetch_add(complete.len() as u64, Ordering::Relaxed);

            streams.remove(&header.stream_id);
            return Ok(Some(complete));
        }

        Ok(None)
    }

    /// Clean up timed-out streams
    pub fn cleanup_timeouts(&self) -> usize {
        let now = crate::time::timestamp_millis();
        let mut streams = self.streams.lock();
        let mut timed_out = Vec::new();

        for (&stream_id, state) in streams.iter() {
            if now.saturating_sub(state.started_ms) > STREAM_TIMEOUT_MS {
                timed_out.push(stream_id);
            }
        }

        let count = timed_out.len();
        for stream_id in timed_out {
            streams.remove(&stream_id);
            self.stats.streams_timed_out.fetch_add(1, Ordering::Relaxed);
        }

        count
    }

    /// Get number of active streams
    pub fn active_streams(&self) -> usize {
        self.streams.lock().len()
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.frames_received.load(Ordering::Relaxed),
            self.stats.streams_completed.load(Ordering::Relaxed),
            self.stats.streams_timed_out.load(Ordering::Relaxed),
            self.stats.bytes_assembled.load(Ordering::Relaxed),
        )
    }
}

impl Default for StreamAssembler {
    fn default() -> Self {
        Self::new()
    }
}

// Global assembler instance
static GLOBAL_ASSEMBLER: StreamAssembler = StreamAssembler::new();

/// Get the global stream assembler
pub fn get_assembler() -> &'static StreamAssembler {
    &GLOBAL_ASSEMBLER
}

// ============================================================================
// Stream ID Generation
// ============================================================================

/// Generate a unique stream ID
fn next_stream_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let salt = crate::time::timestamp_millis();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix timestamp and counter for uniqueness
    salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ counter
}

// ============================================================================
// Tests
// ============================================================================

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

    #[test]
    fn test_error_display() {
        let err = TransportError::InvalidMagic {
            expected: FRAME_MAGIC,
            found: 0xDEADBEEF,
        };
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("0x5354524D"));
        assert!(msg.contains("DEADBEEF"));

        let err = TransportError::SequenceOutOfRange { seq: 5, total: 3 };
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
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
