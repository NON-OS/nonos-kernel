// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// UDP protocol type tests

use crate::network::udp::types::{UdpHeader, UdpPacket, UdpState, UdpStats};
use crate::test::framework::TestResult;
use alloc::vec;

pub(crate) fn test_udp_state_unbound() -> TestResult {
    let state = UdpState::Unbound;
    if state != UdpState::Unbound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_state_bound() -> TestResult {
    let state = UdpState::Bound;
    if state != UdpState::Bound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_state_connected() -> TestResult {
    let state = UdpState::Connected;
    if state != UdpState::Connected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_state_closed() -> TestResult {
    let state = UdpState::Closed;
    if state != UdpState::Closed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_state_equality() -> TestResult {
    if UdpState::Bound != UdpState::Bound {
        return TestResult::Fail;
    }
    if UdpState::Bound == UdpState::Connected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_state_clone() -> TestResult {
    let state = UdpState::Connected;
    let cloned = state.clone();
    if state != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_stats_default() -> TestResult {
    let stats = UdpStats::default();
    if stats.packets_sent != 0 {
        return TestResult::Fail;
    }
    if stats.packets_received != 0 {
        return TestResult::Fail;
    }
    if stats.bytes_sent != 0 {
        return TestResult::Fail;
    }
    if stats.bytes_received != 0 {
        return TestResult::Fail;
    }
    if stats.errors != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_stats_fields() -> TestResult {
    let stats = UdpStats {
        packets_sent: 100,
        packets_received: 150,
        bytes_sent: 5000,
        bytes_received: 7500,
        errors: 2,
    };
    if stats.packets_sent != 100 {
        return TestResult::Fail;
    }
    if stats.packets_received != 150 {
        return TestResult::Fail;
    }
    if stats.bytes_sent != 5000 {
        return TestResult::Fail;
    }
    if stats.bytes_received != 7500 {
        return TestResult::Fail;
    }
    if stats.errors != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_stats_clone() -> TestResult {
    let stats = UdpStats {
        packets_sent: 10,
        packets_received: 20,
        bytes_sent: 500,
        bytes_received: 1000,
        errors: 1,
    };
    let cloned = stats.clone();
    if stats.packets_sent != cloned.packets_sent {
        return TestResult::Fail;
    }
    if stats.packets_received != cloned.packets_received {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_parse_valid() -> TestResult {
    let data = [
        0x30, 0x39, // src_port: 12345
        0x00, 0x50, // dst_port: 80
        0x00, 0x10, // length: 16
        0xAB, 0xCD, // checksum
    ];
    let header = match UdpHeader::parse(&data) {
        Some(h) => h,
        None => return TestResult::Fail,
    };
    if header.src_port != 12345 {
        return TestResult::Fail;
    }
    if header.dst_port != 80 {
        return TestResult::Fail;
    }
    if header.length != 16 {
        return TestResult::Fail;
    }
    if header.checksum != 0xABCD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_parse_too_short() -> TestResult {
    let data = [0x30, 0x39, 0x00, 0x50, 0x00]; // Only 5 bytes
    let result = UdpHeader::parse(&data);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_parse_empty() -> TestResult {
    let data: [u8; 0] = [];
    let result = UdpHeader::parse(&data);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_parse_exact_size() -> TestResult {
    let data = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    let header = match UdpHeader::parse(&data) {
        Some(h) => h,
        None => return TestResult::Fail,
    };
    if header.src_port != 53 {
        return TestResult::Fail;
    }
    if header.dst_port != 53 {
        return TestResult::Fail;
    }
    if header.length != 8 {
        return TestResult::Fail;
    }
    if header.checksum != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_serialize() -> TestResult {
    let header = UdpHeader { src_port: 12345, dst_port: 80, length: 16, checksum: 0xABCD };
    let bytes = header.serialize();
    if bytes[0] != 0x30 {
        return TestResult::Fail;
    }
    if bytes[1] != 0x39 {
        return TestResult::Fail;
    }
    if bytes[2] != 0x00 {
        return TestResult::Fail;
    }
    if bytes[3] != 0x50 {
        return TestResult::Fail;
    }
    if bytes[4] != 0x00 {
        return TestResult::Fail;
    }
    if bytes[5] != 0x10 {
        return TestResult::Fail;
    }
    if bytes[6] != 0xAB {
        return TestResult::Fail;
    }
    if bytes[7] != 0xCD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_serialize_roundtrip() -> TestResult {
    let original = UdpHeader { src_port: 443, dst_port: 8080, length: 100, checksum: 0x1234 };
    let bytes = original.serialize();
    let parsed = match UdpHeader::parse(&bytes) {
        Some(h) => h,
        None => return TestResult::Fail,
    };
    if original.src_port != parsed.src_port {
        return TestResult::Fail;
    }
    if original.dst_port != parsed.dst_port {
        return TestResult::Fail;
    }
    if original.length != parsed.length {
        return TestResult::Fail;
    }
    if original.checksum != parsed.checksum {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_clone() -> TestResult {
    let header = UdpHeader { src_port: 53, dst_port: 53, length: 512, checksum: 0xFFFF };
    let cloned = header.clone();
    if header.src_port != cloned.src_port {
        return TestResult::Fail;
    }
    if header.dst_port != cloned.dst_port {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_max_port() -> TestResult {
    let header = UdpHeader { src_port: 65535, dst_port: 65535, length: 8, checksum: 0 };
    let bytes = header.serialize();
    let parsed = match UdpHeader::parse(&bytes) {
        Some(h) => h,
        None => return TestResult::Fail,
    };
    if parsed.src_port != 65535 {
        return TestResult::Fail;
    }
    if parsed.dst_port != 65535 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_min_length() -> TestResult {
    let header = UdpHeader { src_port: 1024, dst_port: 1025, length: 8, checksum: 0 };
    if header.length != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_packet_fields() -> TestResult {
    let packet = UdpPacket {
        src_addr: [192, 168, 1, 1],
        src_port: 12345,
        data: vec![1, 2, 3, 4],
        timestamp: 1000,
    };
    if packet.src_addr != [192, 168, 1, 1] {
        return TestResult::Fail;
    }
    if packet.src_port != 12345 {
        return TestResult::Fail;
    }
    if packet.data != vec![1, 2, 3, 4] {
        return TestResult::Fail;
    }
    if packet.timestamp != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_packet_clone() -> TestResult {
    let packet = UdpPacket {
        src_addr: [10, 0, 0, 1],
        src_port: 53,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        timestamp: 500,
    };
    let cloned = packet.clone();
    if packet.src_addr != cloned.src_addr {
        return TestResult::Fail;
    }
    if packet.src_port != cloned.src_port {
        return TestResult::Fail;
    }
    if packet.data != cloned.data {
        return TestResult::Fail;
    }
    if packet.timestamp != cloned.timestamp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_packet_empty_data() -> TestResult {
    let packet = UdpPacket { src_addr: [0; 4], src_port: 0, data: vec![], timestamp: 0 };
    if !packet.data.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_calculate_checksum() -> TestResult {
    let src_ip = [192, 168, 1, 1];
    let dst_ip = [192, 168, 1, 2];
    let data = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    let checksum = UdpHeader::calculate_checksum(src_ip, dst_ip, &data);
    if checksum == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_calculate_checksum_empty_data() -> TestResult {
    let src_ip = [10, 0, 0, 1];
    let dst_ip = [10, 0, 0, 2];
    let data: [u8; 0] = [];
    let checksum = UdpHeader::calculate_checksum(src_ip, dst_ip, &data);
    if checksum == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_udp_header_calculate_checksum_odd_length() -> TestResult {
    let src_ip = [172, 16, 0, 1];
    let dst_ip = [172, 16, 0, 2];
    let data = [0x01, 0x02, 0x03];
    let checksum = UdpHeader::calculate_checksum(src_ip, dst_ip, &data);
    if checksum == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
