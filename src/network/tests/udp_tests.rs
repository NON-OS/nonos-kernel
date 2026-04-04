use crate::network::udp::types::{UdpState, UdpStats, UdpHeader, UdpPacket};
use alloc::vec;

#[test]
fn test_udp_state_unbound() {
    let state = UdpState::Unbound;
    assert_eq!(state, UdpState::Unbound);
}

#[test]
fn test_udp_state_bound() {
    let state = UdpState::Bound;
    assert_eq!(state, UdpState::Bound);
}

#[test]
fn test_udp_state_connected() {
    let state = UdpState::Connected;
    assert_eq!(state, UdpState::Connected);
}

#[test]
fn test_udp_state_closed() {
    let state = UdpState::Closed;
    assert_eq!(state, UdpState::Closed);
}

#[test]
fn test_udp_state_equality() {
    assert_eq!(UdpState::Bound, UdpState::Bound);
    assert_ne!(UdpState::Bound, UdpState::Connected);
}

#[test]
fn test_udp_state_clone() {
    let state = UdpState::Connected;
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
fn test_udp_stats_default() {
    let stats = UdpStats::default();
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.errors, 0);
}

#[test]
fn test_udp_stats_fields() {
    let stats = UdpStats {
        packets_sent: 100,
        packets_received: 150,
        bytes_sent: 5000,
        bytes_received: 7500,
        errors: 2,
    };
    assert_eq!(stats.packets_sent, 100);
    assert_eq!(stats.packets_received, 150);
    assert_eq!(stats.bytes_sent, 5000);
    assert_eq!(stats.bytes_received, 7500);
    assert_eq!(stats.errors, 2);
}

#[test]
fn test_udp_stats_clone() {
    let stats = UdpStats {
        packets_sent: 10,
        packets_received: 20,
        bytes_sent: 500,
        bytes_received: 1000,
        errors: 1,
    };
    let cloned = stats.clone();
    assert_eq!(stats.packets_sent, cloned.packets_sent);
    assert_eq!(stats.packets_received, cloned.packets_received);
}

#[test]
fn test_udp_header_parse_valid() {
    let data = [
        0x30, 0x39, // src_port: 12345
        0x00, 0x50, // dst_port: 80
        0x00, 0x10, // length: 16
        0xAB, 0xCD, // checksum
    ];
    let header = UdpHeader::parse(&data).unwrap();
    assert_eq!(header.src_port, 12345);
    assert_eq!(header.dst_port, 80);
    assert_eq!(header.length, 16);
    assert_eq!(header.checksum, 0xABCD);
}

#[test]
fn test_udp_header_parse_too_short() {
    let data = [0x30, 0x39, 0x00, 0x50, 0x00]; // Only 5 bytes
    let result = UdpHeader::parse(&data);
    assert!(result.is_none());
}

#[test]
fn test_udp_header_parse_empty() {
    let data: [u8; 0] = [];
    let result = UdpHeader::parse(&data);
    assert!(result.is_none());
}

#[test]
fn test_udp_header_parse_exact_size() {
    let data = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    let header = UdpHeader::parse(&data).unwrap();
    assert_eq!(header.src_port, 53);
    assert_eq!(header.dst_port, 53);
    assert_eq!(header.length, 8);
    assert_eq!(header.checksum, 0);
}

#[test]
fn test_udp_header_serialize() {
    let header = UdpHeader {
        src_port: 12345,
        dst_port: 80,
        length: 16,
        checksum: 0xABCD,
    };
    let bytes = header.serialize();
    assert_eq!(bytes[0], 0x30);
    assert_eq!(bytes[1], 0x39);
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x50);
    assert_eq!(bytes[4], 0x00);
    assert_eq!(bytes[5], 0x10);
    assert_eq!(bytes[6], 0xAB);
    assert_eq!(bytes[7], 0xCD);
}

#[test]
fn test_udp_header_serialize_roundtrip() {
    let original = UdpHeader {
        src_port: 443,
        dst_port: 8080,
        length: 100,
        checksum: 0x1234,
    };
    let bytes = original.serialize();
    let parsed = UdpHeader::parse(&bytes).unwrap();
    assert_eq!(original.src_port, parsed.src_port);
    assert_eq!(original.dst_port, parsed.dst_port);
    assert_eq!(original.length, parsed.length);
    assert_eq!(original.checksum, parsed.checksum);
}

#[test]
fn test_udp_header_clone() {
    let header = UdpHeader {
        src_port: 53,
        dst_port: 53,
        length: 512,
        checksum: 0xFFFF,
    };
    let cloned = header.clone();
    assert_eq!(header.src_port, cloned.src_port);
    assert_eq!(header.dst_port, cloned.dst_port);
}

#[test]
fn test_udp_header_max_port() {
    let header = UdpHeader {
        src_port: 65535,
        dst_port: 65535,
        length: 8,
        checksum: 0,
    };
    let bytes = header.serialize();
    let parsed = UdpHeader::parse(&bytes).unwrap();
    assert_eq!(parsed.src_port, 65535);
    assert_eq!(parsed.dst_port, 65535);
}

#[test]
fn test_udp_header_min_length() {
    let header = UdpHeader {
        src_port: 1024,
        dst_port: 1025,
        length: 8,
        checksum: 0,
    };
    assert_eq!(header.length, 8);
}

#[test]
fn test_udp_packet_fields() {
    let packet = UdpPacket {
        src_addr: [192, 168, 1, 1],
        src_port: 12345,
        data: vec![1, 2, 3, 4],
        timestamp: 1000,
    };
    assert_eq!(packet.src_addr, [192, 168, 1, 1]);
    assert_eq!(packet.src_port, 12345);
    assert_eq!(packet.data, vec![1, 2, 3, 4]);
    assert_eq!(packet.timestamp, 1000);
}

#[test]
fn test_udp_packet_clone() {
    let packet = UdpPacket {
        src_addr: [10, 0, 0, 1],
        src_port: 53,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        timestamp: 500,
    };
    let cloned = packet.clone();
    assert_eq!(packet.src_addr, cloned.src_addr);
    assert_eq!(packet.src_port, cloned.src_port);
    assert_eq!(packet.data, cloned.data);
    assert_eq!(packet.timestamp, cloned.timestamp);
}

#[test]
fn test_udp_packet_empty_data() {
    let packet = UdpPacket {
        src_addr: [0; 4],
        src_port: 0,
        data: vec![],
        timestamp: 0,
    };
    assert!(packet.data.is_empty());
}

#[test]
fn test_udp_header_calculate_checksum() {
    let src_ip = [192, 168, 1, 1];
    let dst_ip = [192, 168, 1, 2];
    let data = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    let checksum = UdpHeader::calculate_checksum(src_ip, dst_ip, &data);
    assert_ne!(checksum, 0);
}

#[test]
fn test_udp_header_calculate_checksum_empty_data() {
    let src_ip = [10, 0, 0, 1];
    let dst_ip = [10, 0, 0, 2];
    let data: [u8; 0] = [];
    let checksum = UdpHeader::calculate_checksum(src_ip, dst_ip, &data);
    assert_ne!(checksum, 0);
}

#[test]
fn test_udp_header_calculate_checksum_odd_length() {
    let src_ip = [172, 16, 0, 1];
    let dst_ip = [172, 16, 0, 2];
    let data = [0x01, 0x02, 0x03];
    let checksum = UdpHeader::calculate_checksum(src_ip, dst_ip, &data);
    assert_ne!(checksum, 0);
}
