// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::nonos_transport::error::TransportError;
use crate::ipc::nonos_transport::frame::{
    FrameHeader, FRAME_MAGIC, FRAME_VERSION, FLAG_EOF, FRAME_HEADER_SIZE, parse_frame,
};

#[test]
fn test_frame_magic_constant() {
    assert_eq!(FRAME_MAGIC, 0x5354_524D);
}

#[test]
fn test_frame_version_constant() {
    assert_eq!(FRAME_VERSION, 1);
}

#[test]
fn test_flag_eof_constant() {
    assert_eq!(FLAG_EOF, 0x01);
}

#[test]
fn test_frame_header_size_constant() {
    assert_eq!(FRAME_HEADER_SIZE, 23);
}

#[test]
fn test_frame_header_is_eof_true() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: FLAG_EOF,
    };
    assert!(header.is_eof());
}

#[test]
fn test_frame_header_is_eof_false() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 2,
        flags: 0,
    };
    assert!(!header.is_eof());
}

#[test]
fn test_frame_header_to_bytes_size() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), FRAME_HEADER_SIZE);
}

#[test]
fn test_frame_header_to_bytes_magic() {
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
    assert_eq!(magic, FRAME_MAGIC);
}

#[test]
fn test_frame_header_to_bytes_version() {
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
    assert_eq!(version, FRAME_VERSION);
}

#[test]
fn test_frame_header_to_bytes_stream_id() {
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
        bytes[6], bytes[7], bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13],
    ]);
    assert_eq!(stream_id, 0x1234_5678_9ABC_DEF0);
}

#[test]
fn test_frame_header_to_bytes_seq() {
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
    assert_eq!(seq, 42);
}

#[test]
fn test_frame_header_to_bytes_total() {
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
    assert_eq!(total, 100);
}

#[test]
fn test_frame_header_to_bytes_flags() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: FLAG_EOF,
    };
    let bytes = header.to_bytes();
    assert_eq!(bytes[22], FLAG_EOF);
}

#[test]
fn test_frame_header_from_bytes_valid() {
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
    assert_eq!(parsed.magic, FRAME_MAGIC);
    assert_eq!(parsed.version, FRAME_VERSION);
    assert_eq!(parsed.stream_id, 123);
    assert_eq!(parsed.seq, 5);
    assert_eq!(parsed.total, 10);
    assert_eq!(parsed.flags, FLAG_EOF);
}

#[test]
fn test_frame_header_from_bytes_invalid_magic() {
    let mut bytes = [0u8; FRAME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let result = FrameHeader::from_bytes(&bytes);
    assert!(matches!(result, Err(TransportError::InvalidMagic { expected: _, found: 0xDEAD_BEEF })));
}

#[test]
fn test_frame_header_from_bytes_unsupported_version() {
    let mut bytes = [0u8; FRAME_HEADER_SIZE];
    bytes[0..4].copy_from_slice(&FRAME_MAGIC.to_le_bytes());
    bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
    let result = FrameHeader::from_bytes(&bytes);
    assert!(matches!(result, Err(TransportError::UnsupportedVersion { version: 99 })));
}

#[test]
fn test_frame_header_from_bytes_frame_too_short() {
    let bytes = [0u8; 10];
    let result = FrameHeader::from_bytes(&bytes);
    assert!(matches!(result, Err(TransportError::FrameTooShort { size: 10, minimum: 23 })));
}

#[test]
fn test_frame_header_from_bytes_sequence_out_of_range() {
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
    assert!(matches!(result, Err(TransportError::SequenceOutOfRange { seq: 10, total: 5 })));
}

#[test]
fn test_frame_header_from_bytes_zero_total_allowed() {
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
    assert!(result.is_ok());
}

#[test]
fn test_frame_header_roundtrip() {
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
    assert_eq!(parsed, header);
}

#[test]
fn test_frame_header_clone() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let cloned = header.clone();
    assert_eq!(header, cloned);
}

#[test]
fn test_frame_header_copy() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let copied = header;
    assert_eq!(header, copied);
}

#[test]
fn test_frame_header_debug() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 1,
        flags: 0,
    };
    let debug_str = alloc::format!("{:?}", header);
    assert!(debug_str.contains("FrameHeader"));
}

#[test]
fn test_transport_error_invalid_magic_as_str() {
    let err = TransportError::InvalidMagic { expected: FRAME_MAGIC, found: 0 };
    assert_eq!(err.as_str(), "Invalid frame magic number");
}

#[test]
fn test_transport_error_unsupported_version_as_str() {
    let err = TransportError::UnsupportedVersion { version: 99 };
    assert_eq!(err.as_str(), "Unsupported frame version");
}

#[test]
fn test_transport_error_frame_too_short_as_str() {
    let err = TransportError::FrameTooShort { size: 10, minimum: 23 };
    assert_eq!(err.as_str(), "Frame too short for header");
}

#[test]
fn test_transport_error_sequence_out_of_range_as_str() {
    let err = TransportError::SequenceOutOfRange { seq: 10, total: 5 };
    assert_eq!(err.as_str(), "Sequence number out of range");
}

#[test]
fn test_transport_error_duplicate_frame_as_str() {
    let err = TransportError::DuplicateFrame { stream_id: 1, seq: 0 };
    assert_eq!(err.as_str(), "Duplicate frame received");
}

#[test]
fn test_transport_error_stream_not_found_as_str() {
    let err = TransportError::StreamNotFound { stream_id: 1 };
    assert_eq!(err.as_str(), "Stream not found");
}

#[test]
fn test_transport_error_mtu_too_small_as_str() {
    let err = TransportError::MtuTooSmall { mtu: 32, minimum: 64 };
    assert_eq!(err.as_str(), "MTU too small");
}

#[test]
fn test_transport_error_mtu_too_large_as_str() {
    let err = TransportError::MtuTooLarge { mtu: 100000, maximum: 65535 };
    assert_eq!(err.as_str(), "MTU too large");
}

#[test]
fn test_transport_error_payload_too_large_as_str() {
    let err = TransportError::PayloadTooLarge { size: 100000, maximum: 65536 };
    assert_eq!(err.as_str(), "Payload exceeds maximum size");
}

#[test]
fn test_transport_error_transmit_failed_as_str() {
    let err = TransportError::TransmitFailed;
    assert_eq!(err.as_str(), "Transmission failed");
}

#[test]
fn test_transport_error_assembly_timeout_as_str() {
    let err = TransportError::AssemblyTimeout { stream_id: 1 };
    assert_eq!(err.as_str(), "Assembly timeout");
}

#[test]
fn test_transport_error_too_many_streams_as_str() {
    let err = TransportError::TooManyStreams { count: 100, limit: 64 };
    assert_eq!(err.as_str(), "Too many concurrent streams");
}

#[test]
fn test_transport_error_display_invalid_magic() {
    let err = TransportError::InvalidMagic { expected: FRAME_MAGIC, found: 0xDEADBEEF };
    let display = alloc::format!("{}", err);
    assert!(display.contains("5354524D"));
    assert!(display.contains("DEADBEEF"));
}

#[test]
fn test_transport_error_display_unsupported_version() {
    let err = TransportError::UnsupportedVersion { version: 99 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("99"));
}

#[test]
fn test_transport_error_display_frame_too_short() {
    let err = TransportError::FrameTooShort { size: 10, minimum: 23 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("10"));
    assert!(display.contains("23"));
}

#[test]
fn test_transport_error_display_sequence_out_of_range() {
    let err = TransportError::SequenceOutOfRange { seq: 10, total: 5 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("10"));
    assert!(display.contains("5"));
}

#[test]
fn test_transport_error_display_mtu_too_small() {
    let err = TransportError::MtuTooSmall { mtu: 32, minimum: 64 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("32"));
    assert!(display.contains("64"));
}

#[test]
fn test_transport_error_display_payload_too_large() {
    let err = TransportError::PayloadTooLarge { size: 100000, maximum: 65536 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("100000"));
    assert!(display.contains("65536"));
}

#[test]
fn test_transport_error_clone() {
    let err = TransportError::TransmitFailed;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_transport_error_copy() {
    let err = TransportError::TransmitFailed;
    let copied = err;
    assert_eq!(err, copied);
}

#[test]
fn test_transport_error_equality() {
    assert_eq!(TransportError::TransmitFailed, TransportError::TransmitFailed);
    assert_ne!(
        TransportError::TransmitFailed,
        TransportError::UnsupportedVersion { version: 1 }
    );
}

#[test]
fn test_parse_frame_valid() {
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
    assert_eq!(parsed_header.stream_id, 1);
    assert_eq!(parsed_payload, payload);
}

#[test]
fn test_parse_frame_empty_payload() {
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
    assert_eq!(parsed_header.stream_id, 1);
    assert!(parsed_payload.is_empty());
}

#[test]
fn test_parse_frame_invalid() {
    let bytes = [0u8; 10];
    let result = parse_frame(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_frame_header_first_frame() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 0,
        total: 10,
        flags: 0,
    };
    assert!(!header.is_eof());
    assert_eq!(header.seq, 0);
}

#[test]
fn test_frame_header_last_frame() {
    let header = FrameHeader {
        magic: FRAME_MAGIC,
        version: FRAME_VERSION,
        stream_id: 1,
        seq: 9,
        total: 10,
        flags: FLAG_EOF,
    };
    assert!(header.is_eof());
    assert_eq!(header.seq, 9);
}

#[test]
fn test_transport_error_all_variants_have_str() {
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
        assert!(!err.as_str().is_empty());
    }
}

