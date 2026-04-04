// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::ethernet::types::{
    EtherType, ETHERTYPE_IP, ETHERTYPE_IPV6, ETHERTYPE_ARP,
};

#[test]
fn test_ethertype_ip_constant() {
    assert_eq!(ETHERTYPE_IP, 0x0800);
}

#[test]
fn test_ethertype_ipv6_constant() {
    assert_eq!(ETHERTYPE_IPV6, 0x86DD);
}

#[test]
fn test_ethertype_arp_constant() {
    assert_eq!(ETHERTYPE_ARP, 0x0806);
}

#[test]
fn test_ethertypes_unique() {
    assert_ne!(ETHERTYPE_IP, ETHERTYPE_IPV6);
    assert_ne!(ETHERTYPE_IP, ETHERTYPE_ARP);
    assert_ne!(ETHERTYPE_IPV6, ETHERTYPE_ARP);
}

#[test]
fn test_ethertype_ipv4_variant() {
    let et = EtherType::Ipv4;
    assert_eq!(et, EtherType::Ipv4);
}

#[test]
fn test_ethertype_ipv6_variant() {
    let et = EtherType::Ipv6;
    assert_eq!(et, EtherType::Ipv6);
}

#[test]
fn test_ethertype_arp_variant() {
    let et = EtherType::Arp;
    assert_eq!(et, EtherType::Arp);
}

#[test]
fn test_ethertype_other_variant() {
    let et = EtherType::Other(0x1234);
    if let EtherType::Other(val) = et {
        assert_eq!(val, 0x1234);
    } else {
        panic!("Expected Other variant");
    }
}

#[test]
fn test_ethertype_from_u16_ipv4() {
    let et = EtherType::from_u16(0x0800);
    assert_eq!(et, EtherType::Ipv4);
}

#[test]
fn test_ethertype_from_u16_ipv6() {
    let et = EtherType::from_u16(0x86DD);
    assert_eq!(et, EtherType::Ipv6);
}

#[test]
fn test_ethertype_from_u16_arp() {
    let et = EtherType::from_u16(0x0806);
    assert_eq!(et, EtherType::Arp);
}

#[test]
fn test_ethertype_from_u16_other() {
    let et = EtherType::from_u16(0x9999);
    assert_eq!(et, EtherType::Other(0x9999));
}

#[test]
fn test_ethertype_from_u16_zero() {
    let et = EtherType::from_u16(0x0000);
    assert_eq!(et, EtherType::Other(0x0000));
}

#[test]
fn test_ethertype_to_u16_ipv4() {
    let et = EtherType::Ipv4;
    assert_eq!(et.to_u16(), 0x0800);
}

#[test]
fn test_ethertype_to_u16_ipv6() {
    let et = EtherType::Ipv6;
    assert_eq!(et.to_u16(), 0x86DD);
}

#[test]
fn test_ethertype_to_u16_arp() {
    let et = EtherType::Arp;
    assert_eq!(et.to_u16(), 0x0806);
}

#[test]
fn test_ethertype_to_u16_other() {
    let et = EtherType::Other(0xABCD);
    assert_eq!(et.to_u16(), 0xABCD);
}

#[test]
fn test_ethertype_roundtrip_ipv4() {
    let original = ETHERTYPE_IP;
    let et = EtherType::from_u16(original);
    assert_eq!(et.to_u16(), original);
}

#[test]
fn test_ethertype_roundtrip_ipv6() {
    let original = ETHERTYPE_IPV6;
    let et = EtherType::from_u16(original);
    assert_eq!(et.to_u16(), original);
}

#[test]
fn test_ethertype_roundtrip_arp() {
    let original = ETHERTYPE_ARP;
    let et = EtherType::from_u16(original);
    assert_eq!(et.to_u16(), original);
}

#[test]
fn test_ethertype_roundtrip_other() {
    let original = 0x5678u16;
    let et = EtherType::from_u16(original);
    assert_eq!(et.to_u16(), original);
}

#[test]
fn test_ethertype_clone() {
    let et = EtherType::Ipv4;
    let cloned = et.clone();
    assert_eq!(et, cloned);
}

#[test]
fn test_ethertype_copy() {
    let et1 = EtherType::Ipv6;
    let et2 = et1;
    assert_eq!(et1, et2);
}

#[test]
fn test_ethertype_equality() {
    assert_eq!(EtherType::Ipv4, EtherType::Ipv4);
    assert_eq!(EtherType::Ipv6, EtherType::Ipv6);
    assert_eq!(EtherType::Arp, EtherType::Arp);
    assert_eq!(EtherType::Other(100), EtherType::Other(100));
}

#[test]
fn test_ethertype_inequality() {
    assert_ne!(EtherType::Ipv4, EtherType::Ipv6);
    assert_ne!(EtherType::Ipv4, EtherType::Arp);
    assert_ne!(EtherType::Other(100), EtherType::Other(200));
}

#[test]
fn test_ethertype_debug() {
    let et = EtherType::Ipv4;
    let debug_str = alloc::format!("{:?}", et);
    assert!(debug_str.contains("Ipv4"));
}

#[test]
fn test_ethertype_debug_other() {
    let et = EtherType::Other(0x1234);
    let debug_str = alloc::format!("{:?}", et);
    assert!(debug_str.contains("Other"));
}

#[test]
fn test_ethertype_all_known_values() {
    let types = [EtherType::Ipv4, EtherType::Ipv6, EtherType::Arp];
    let values = [0x0800u16, 0x86DD, 0x0806];
    for (et, val) in types.iter().zip(values.iter()) {
        assert_eq!(et.to_u16(), *val);
    }
}

#[test]
fn test_ethertype_from_all_known_values() {
    let values = [0x0800u16, 0x86DD, 0x0806];
    let expected = [EtherType::Ipv4, EtherType::Ipv6, EtherType::Arp];
    for (val, exp) in values.iter().zip(expected.iter()) {
        assert_eq!(EtherType::from_u16(*val), *exp);
    }
}

#[test]
fn test_ethertype_max_value() {
    let et = EtherType::from_u16(u16::MAX);
    assert_eq!(et, EtherType::Other(u16::MAX));
    assert_eq!(et.to_u16(), u16::MAX);
}

#[test]
fn test_ethertype_common_protocols() {
    assert_eq!(EtherType::from_u16(0x8100).to_u16(), 0x8100);
    assert_eq!(EtherType::from_u16(0x88A8).to_u16(), 0x88A8);
}

