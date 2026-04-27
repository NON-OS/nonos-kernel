// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Ethernet frame type tests

use crate::network::ethernet::types::{EtherType, ETHERTYPE_ARP, ETHERTYPE_IP, ETHERTYPE_IPV6};
use crate::test::framework::TestResult;

pub(crate) fn test_ethertype_ip_constant() -> TestResult {
    if ETHERTYPE_IP != 0x0800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_ipv6_constant() -> TestResult {
    if ETHERTYPE_IPV6 != 0x86DD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_arp_constant() -> TestResult {
    if ETHERTYPE_ARP != 0x0806 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertypes_unique() -> TestResult {
    if ETHERTYPE_IP == ETHERTYPE_IPV6 {
        return TestResult::Fail;
    }
    if ETHERTYPE_IP == ETHERTYPE_ARP {
        return TestResult::Fail;
    }
    if ETHERTYPE_IPV6 == ETHERTYPE_ARP {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_ipv4_variant() -> TestResult {
    let et = EtherType::Ipv4;
    if et != EtherType::Ipv4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_ipv6_variant() -> TestResult {
    let et = EtherType::Ipv6;
    if et != EtherType::Ipv6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_arp_variant() -> TestResult {
    let et = EtherType::Arp;
    if et != EtherType::Arp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_other_variant() -> TestResult {
    let et = EtherType::Other(0x1234);
    if let EtherType::Other(val) = et {
        if val != 0x1234 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_from_u16_ipv4() -> TestResult {
    let et = EtherType::from_u16(0x0800);
    if et != EtherType::Ipv4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_from_u16_ipv6() -> TestResult {
    let et = EtherType::from_u16(0x86DD);
    if et != EtherType::Ipv6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_from_u16_arp() -> TestResult {
    let et = EtherType::from_u16(0x0806);
    if et != EtherType::Arp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_from_u16_other() -> TestResult {
    let et = EtherType::from_u16(0x9999);
    if et != EtherType::Other(0x9999) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_from_u16_zero() -> TestResult {
    let et = EtherType::from_u16(0x0000);
    if et != EtherType::Other(0x0000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_to_u16_ipv4() -> TestResult {
    let et = EtherType::Ipv4;
    if et.to_u16() != 0x0800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_to_u16_ipv6() -> TestResult {
    let et = EtherType::Ipv6;
    if et.to_u16() != 0x86DD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_to_u16_arp() -> TestResult {
    let et = EtherType::Arp;
    if et.to_u16() != 0x0806 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_to_u16_other() -> TestResult {
    let et = EtherType::Other(0xABCD);
    if et.to_u16() != 0xABCD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_roundtrip_ipv4() -> TestResult {
    let original = ETHERTYPE_IP;
    let et = EtherType::from_u16(original);
    if et.to_u16() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_roundtrip_ipv6() -> TestResult {
    let original = ETHERTYPE_IPV6;
    let et = EtherType::from_u16(original);
    if et.to_u16() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_roundtrip_arp() -> TestResult {
    let original = ETHERTYPE_ARP;
    let et = EtherType::from_u16(original);
    if et.to_u16() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_roundtrip_other() -> TestResult {
    let original = 0x5678u16;
    let et = EtherType::from_u16(original);
    if et.to_u16() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_clone() -> TestResult {
    let et = EtherType::Ipv4;
    let cloned = et.clone();
    if et != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_copy() -> TestResult {
    let et1 = EtherType::Ipv6;
    let et2 = et1;
    if et1 != et2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_equality() -> TestResult {
    if EtherType::Ipv4 != EtherType::Ipv4 {
        return TestResult::Fail;
    }
    if EtherType::Ipv6 != EtherType::Ipv6 {
        return TestResult::Fail;
    }
    if EtherType::Arp != EtherType::Arp {
        return TestResult::Fail;
    }
    if EtherType::Other(100) != EtherType::Other(100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_inequality() -> TestResult {
    if EtherType::Ipv4 == EtherType::Ipv6 {
        return TestResult::Fail;
    }
    if EtherType::Ipv4 == EtherType::Arp {
        return TestResult::Fail;
    }
    if EtherType::Other(100) == EtherType::Other(200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_debug() -> TestResult {
    let et = EtherType::Ipv4;
    let debug_str = alloc::format!("{:?}", et);
    if !debug_str.contains("Ipv4") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_debug_other() -> TestResult {
    let et = EtherType::Other(0x1234);
    let debug_str = alloc::format!("{:?}", et);
    if !debug_str.contains("Other") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_all_known_values() -> TestResult {
    let types = [EtherType::Ipv4, EtherType::Ipv6, EtherType::Arp];
    let values = [0x0800u16, 0x86DD, 0x0806];
    for (et, val) in types.iter().zip(values.iter()) {
        if et.to_u16() != *val {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_from_all_known_values() -> TestResult {
    let values = [0x0800u16, 0x86DD, 0x0806];
    let expected = [EtherType::Ipv4, EtherType::Ipv6, EtherType::Arp];
    for (val, exp) in values.iter().zip(expected.iter()) {
        if EtherType::from_u16(*val) != *exp {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_max_value() -> TestResult {
    let et = EtherType::from_u16(u16::MAX);
    if et != EtherType::Other(u16::MAX) {
        return TestResult::Fail;
    }
    if et.to_u16() != u16::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ethertype_common_protocols() -> TestResult {
    // VLAN tagged frame
    if EtherType::from_u16(0x8100).to_u16() != 0x8100 {
        return TestResult::Fail;
    }
    // QinQ
    if EtherType::from_u16(0x88A8).to_u16() != 0x88A8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
