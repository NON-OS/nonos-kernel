// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// IP protocol type tests

use crate::network::ip::types::{IpAddress, IP_PROTOCOL_ICMP, IP_PROTOCOL_TCP, IP_PROTOCOL_UDP};
use crate::test::framework::TestResult;

pub(crate) fn test_ip_protocol_tcp() -> TestResult {
    if IP_PROTOCOL_TCP != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_protocol_udp() -> TestResult {
    if IP_PROTOCOL_UDP != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_protocol_icmp() -> TestResult {
    if IP_PROTOCOL_ICMP != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_protocols_unique() -> TestResult {
    if IP_PROTOCOL_TCP == IP_PROTOCOL_UDP {
        return TestResult::Fail;
    }
    if IP_PROTOCOL_TCP == IP_PROTOCOL_ICMP {
        return TestResult::Fail;
    }
    if IP_PROTOCOL_UDP == IP_PROTOCOL_ICMP {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_v4_create() -> TestResult {
    let addr = IpAddress::v4(192, 168, 1, 1);
    if !addr.is_ipv4() {
        return TestResult::Fail;
    }
    if addr.is_ipv6() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_v4_variant() -> TestResult {
    let addr = IpAddress::V4([10, 0, 0, 1]);
    if !addr.is_ipv4() {
        return TestResult::Fail;
    }
    if addr.is_ipv6() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_v6_variant() -> TestResult {
    let addr = IpAddress::V6([0; 16]);
    if !addr.is_ipv6() {
        return TestResult::Fail;
    }
    if addr.is_ipv4() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_unspecified_v4() -> TestResult {
    let addr = IpAddress::v4(0, 0, 0, 0);
    if !addr.is_unspecified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_unspecified_v6() -> TestResult {
    let addr = IpAddress::V6([0; 16]);
    if !addr.is_unspecified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_not_unspecified_v4() -> TestResult {
    let addr = IpAddress::v4(192, 168, 1, 1);
    if addr.is_unspecified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_not_unspecified_v6() -> TestResult {
    let addr = IpAddress::V6([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    if addr.is_unspecified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_loopback_v4() -> TestResult {
    let addr = IpAddress::v4(127, 0, 0, 1);
    if !addr.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_loopback_v4_any() -> TestResult {
    let addr = IpAddress::v4(127, 1, 2, 3);
    if !addr.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_loopback_v6() -> TestResult {
    let addr = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    if !addr.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_not_loopback_v4() -> TestResult {
    let addr = IpAddress::v4(192, 168, 1, 1);
    if addr.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_not_loopback_v6() -> TestResult {
    let addr = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    if addr.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_equality_v4() -> TestResult {
    let addr1 = IpAddress::v4(192, 168, 1, 1);
    let addr2 = IpAddress::v4(192, 168, 1, 1);
    let addr3 = IpAddress::v4(192, 168, 1, 2);
    if addr1 != addr2 {
        return TestResult::Fail;
    }
    if addr1 == addr3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_equality_v6() -> TestResult {
    let addr1 = IpAddress::V6([1; 16]);
    let addr2 = IpAddress::V6([1; 16]);
    let addr3 = IpAddress::V6([2; 16]);
    if addr1 != addr2 {
        return TestResult::Fail;
    }
    if addr1 == addr3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_v4_v6_different() -> TestResult {
    let v4 = IpAddress::v4(0, 0, 0, 0);
    let v6 = IpAddress::V6([0; 16]);
    if v4 == v6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_clone() -> TestResult {
    let addr = IpAddress::v4(10, 20, 30, 40);
    let cloned = addr.clone();
    if addr != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_copy() -> TestResult {
    let addr1 = IpAddress::v4(1, 2, 3, 4);
    let addr2 = addr1;
    if addr1 != addr2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_ordering_v4() -> TestResult {
    let addr1 = IpAddress::v4(192, 168, 1, 1);
    let addr2 = IpAddress::v4(192, 168, 1, 2);
    if !(addr1 < addr2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_ordering_v6() -> TestResult {
    let addr1 = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let addr2 = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    if !(addr1 < addr2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_common_v4() -> TestResult {
    let localhost = IpAddress::v4(127, 0, 0, 1);
    let private_a = IpAddress::v4(10, 0, 0, 1);
    let private_b = IpAddress::v4(172, 16, 0, 1);
    let private_c = IpAddress::v4(192, 168, 0, 1);

    if !localhost.is_loopback() {
        return TestResult::Fail;
    }
    if private_a.is_loopback() {
        return TestResult::Fail;
    }
    if private_b.is_loopback() {
        return TestResult::Fail;
    }
    if private_c.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_broadcast_v4() -> TestResult {
    let broadcast = IpAddress::v4(255, 255, 255, 255);
    if broadcast.is_unspecified() {
        return TestResult::Fail;
    }
    if broadcast.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_multicast_v4() -> TestResult {
    let multicast = IpAddress::v4(224, 0, 0, 1);
    if multicast.is_unspecified() {
        return TestResult::Fail;
    }
    if multicast.is_loopback() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_all_variants() -> TestResult {
    let addrs = [
        IpAddress::v4(0, 0, 0, 0),
        IpAddress::v4(127, 0, 0, 1),
        IpAddress::v4(192, 168, 1, 1),
        IpAddress::V6([0; 16]),
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ];
    for addr in addrs {
        let cloned = addr.clone();
        if addr != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ip_protocol_ordering() -> TestResult {
    if !(IP_PROTOCOL_ICMP < IP_PROTOCOL_TCP) {
        return TestResult::Fail;
    }
    if !(IP_PROTOCOL_TCP < IP_PROTOCOL_UDP) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_v4_bytes() -> TestResult {
    let addr = IpAddress::V4([192, 168, 1, 100]);
    if let IpAddress::V4(bytes) = addr {
        if bytes[0] != 192 {
            return TestResult::Fail;
        }
        if bytes[1] != 168 {
            return TestResult::Fail;
        }
        if bytes[2] != 1 {
            return TestResult::Fail;
        }
        if bytes[3] != 100 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ip_address_v6_bytes() -> TestResult {
    let addr = IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    if let IpAddress::V6(bytes) = addr {
        if bytes[0] != 0x20 {
            return TestResult::Fail;
        }
        if bytes[1] != 0x01 {
            return TestResult::Fail;
        }
        if bytes[15] != 1 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}
