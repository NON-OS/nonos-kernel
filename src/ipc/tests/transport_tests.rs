// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::transport::{
    parse_frame, FrameHeader, TransportError, FLAG_EOF, FRAME_HEADER_SIZE, FRAME_MAGIC,
    FRAME_VERSION,
};
use crate::test::framework::TestResult;

pub(crate) fn test_frame_magic_constant() -> TestResult {
    if FRAME_MAGIC != 0x5354_524D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_version_constant() -> TestResult {
    if FRAME_VERSION != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flag_eof_constant() -> TestResult {
    if FLAG_EOF != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_size_constant() -> TestResult {
    if FRAME_HEADER_SIZE != 23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_is_eof_true() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: FLAG_EOF,
    };
    if !header.is_eof() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_is_eof_false() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 2,
        flags: 0,
    };
    if header.is_eof() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_size() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let bytes = header.to_bytes();
    if bytes.len() != FRAME_HEADER_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_magic() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != FRAME_MAGIC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_version() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FRAME_VERSION {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_stream_id() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 0x1234_5678_9ABC_DEF0,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let stream_id = u64::from_le_bytes([
        bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
    ]);
    if stream_id != 0x1234_5678_9ABC_DEF0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_seq() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 42,
        total: 100,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let seq = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
    if seq != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_total() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 100,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let total = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
    if total != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_to_bytes_flags() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: FLAG_EOF,
    };
    let bytes = header.to_bytes();
    if bytes[22] != FLAG_EOF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_from_bytes_valid() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 123,
        seq: 5,
        total: 10,
        flags: FLAG_EOF,
    };
    let bytes = header.to_bytes();
    let parsed = FrameHeader::from_bytes(&bytes).unwrap();
    if parsed.magic != FRAME_MAGIC {
        return TestResult::Fail;
    }
    if parsed.version != FRAME_VERSION {
        return TestResult::Fail;
    }
    if parsed.stream_id != 123 {
        return TestResult::Fail;
    }
    if parsed.seq != 5 {
        return TestResult::Fail;
    }
    if parsed.total != 10 {
        return TestResult::Fail;
    }
    if parsed.flags != FLAG_EOF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_from_bytes_invalid_magic() -> TestResult {
    let mut bytes = [0u8; FRAME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let result = FrameHeader::from_bytes(&bytes);
    if !matches!(result, Err(TransportError::InvalidMagic { expected: _, found: 0xDEAD_BEEF })) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_from_bytes_unsupported_version() -> TestResult {
    let mut bytes = [0u8; FRAME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
    bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
    let result = FrameHeader::from_bytes(&bytes);
    if !matches!(result, Err(TransportError::UnsupportedVersion { version: 99 })) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_from_bytes_frame_too_short() -> TestResult {
    let bytes = [0u8; 10];
    let result = FrameHeader::from_bytes(&bytes);
    if !matches!(result, Err(TransportError::FrameTooShort { size: 10, minimum: 23 })) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_from_bytes_sequence_out_of_range() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 10,
        total: 5,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let result = FrameHeader::from_bytes(&bytes);
    if !matches!(result, Err(TransportError::SequenceOutOfRange { seq: 10, total: 5 })) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_from_bytes_zero_total_allowed() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 5,
        total: 0,
        flags: 0,
    };
    let bytes = header.to_bytes();
    let result = FrameHeader::from_bytes(&bytes);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_roundtrip() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 0xFFFF_FFFF_FFFF_FFFF,
        seq: 999,
        total: 1000,
        flags: 0xFF,
    };
    let bytes = header.to_bytes();
    let parsed = FrameHeader::from_bytes(&bytes).unwrap();
    if parsed != header {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_clone() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let cloned = header.clone();
    if header != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_copy() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let copied = header;
    if header != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_debug() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let debug_str = alloc::format!("{:?}", header);
    if !debug_str.contains("FrameHeader") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_invalid_magic_as_str() -> TestResult {
    let err = TransportError::InvalidMagic { expected: FRAME_MAGIC, found: 0 };
    if err.as_str() != "Invalid frame magic number" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_unsupported_version_as_str() -> TestResult {
    let err = TransportError::UnsupportedVersion { version: 99 };
    if err.as_str() != "Unsupported frame version" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_frame_too_short_as_str() -> TestResult {
    let err = TransportError::FrameTooShort { size: 10, minimum: 23 };
    if err.as_str() != "Frame too short for header" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_sequence_out_of_range_as_str() -> TestResult {
    let err = TransportError::SequenceOutOfRange { seq: 10, total: 5 };
    if err.as_str() != "Sequence number out of range" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_duplicate_frame_as_str() -> TestResult {
    let err = TransportError::DuplicateFrame { stream_id: 1, seq: 0 };
    if err.as_str() != "Duplicate frame received" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_stream_not_found_as_str() -> TestResult {
    let err = TransportError::StreamNotFound { stream_id: 1 };
    if err.as_str() != "Stream not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_mtu_too_small_as_str() -> TestResult {
    let err = TransportError::MtuTooSmall { mtu: 32, minimum: 64 };
    if err.as_str() != "MTU too small" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_mtu_too_large_as_str() -> TestResult {
    let err = TransportError::MtuTooLarge { mtu: 100000, maximum: 65535 };
    if err.as_str() != "MTU too large" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_payload_too_large_as_str() -> TestResult {
    let err = TransportError::PayloadTooLarge { size: 100000, maximum: 65536 };
    if err.as_str() != "Payload exceeds maximum size" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_transmit_failed_as_str() -> TestResult {
    let err = TransportError::TransmitFailed;
    if err.as_str() != "Transmission failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_assembly_timeout_as_str() -> TestResult {
    let err = TransportError::AssemblyTimeout { stream_id: 1 };
    if err.as_str() != "Assembly timeout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_too_many_streams_as_str() -> TestResult {
    let err = TransportError::TooManyStreams { count: 100, limit: 64 };
    if err.as_str() != "Too many concurrent streams" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_display_invalid_magic() -> TestResult {
    let err = TransportError::InvalidMagic { expected: FRAME_MAGIC, found: 0xDEADBEEF };
    let display = alloc::format!("{}", err);
    if !display.contains("5354524D") {
        return TestResult::Fail;
    }
    if !display.contains("DEADBEEF") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_display_unsupported_version() -> TestResult {
    let err = TransportError::UnsupportedVersion { version: 99 };
    let display = alloc::format!("{}", err);
    if !display.contains("99") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_display_frame_too_short() -> TestResult {
    let err = TransportError::FrameTooShort { size: 10, minimum: 23 };
    let display = alloc::format!("{}", err);
    if !display.contains("10") {
        return TestResult::Fail;
    }
    if !display.contains("23") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_display_sequence_out_of_range() -> TestResult {
    let err = TransportError::SequenceOutOfRange { seq: 10, total: 5 };
    let display = alloc::format!("{}", err);
    if !display.contains("10") {
        return TestResult::Fail;
    }
    if !display.contains("5") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_display_mtu_too_small() -> TestResult {
    let err = TransportError::MtuTooSmall { mtu: 32, minimum: 64 };
    let display = alloc::format!("{}", err);
    if !display.contains("32") {
        return TestResult::Fail;
    }
    if !display.contains("64") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_display_payload_too_large() -> TestResult {
    let err = TransportError::PayloadTooLarge { size: 100000, maximum: 65536 };
    let display = alloc::format!("{}", err);
    if !display.contains("100000") {
        return TestResult::Fail;
    }
    if !display.contains("65536") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_clone() -> TestResult {
    let err = TransportError::TransmitFailed;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_copy() -> TestResult {
    let err = TransportError::TransmitFailed;
    let copied = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_equality() -> TestResult {
    if TransportError::TransmitFailed != TransportError::TransmitFailed {
        return TestResult::Fail;
    }
    if TransportError::TransmitFailed == (TransportError::UnsupportedVersion { version: 1 }) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_frame_valid() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: FLAG_EOF,
    };
    let header_bytes = header.to_bytes();
    let payload = b"hello world";
    let mut frame = alloc::vec::Vec::new();
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(payload);

    let (parsed_header, parsed_payload) = parse_frame(&frame).unwrap();
    if parsed_header.stream_id != 1 {
        return TestResult::Fail;
    }
    if parsed_payload != payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_frame_empty_payload() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: FLAG_EOF,
    };
    let frame = header.to_bytes();
    let (parsed_header, parsed_payload) = parse_frame(&frame).unwrap();
    if parsed_header.stream_id != 1 {
        return TestResult::Fail;
    }
    if !parsed_payload.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_frame_invalid() -> TestResult {
    let bytes = [0u8; 10];
    let result = parse_frame(&bytes);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_first_frame() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 10,
        flags: 0,
    };
    if header.is_eof() {
        return TestResult::Fail;
    }
    if header.seq != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_header_last_frame() -> TestResult {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 9,
        total: 10,
        flags: FLAG_EOF,
    };
    if !header.is_eof() {
        return TestResult::Fail;
    }
    if header.seq != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_transport_error_all_variants_have_str() -> TestResult {
    let errors = [
        TransportError::InvalidMagic { expected: 0, found: 0 },
        TransportError::UnsupportedVersion { version: 0 },
        TransportError::FrameTooShort { size: 0, minimum: 0 },
        TransportError::SequenceOutOfRange { seq: 0, total: 0 },
        TransportError::DuplicateFrame { stream_id: 0, seq: 0 },
        TransportError::StreamNotFound { stream_id: 0 },
        TransportError::MtuTooSmall { mtu: 0, minimum: 0 },
        TransportError::MtuTooLarge { mtu: 0, maximum: 0 },
        TransportError::PayloadTooLarge { size: 0, maximum: 0 },
        TransportError::TransmitFailed,
        TransportError::AssemblyTimeout { stream_id: 0 },
        TransportError::TooManyStreams { count: 0, limit: 0 },
    ];
    for err in errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
