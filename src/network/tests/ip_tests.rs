// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::ip::types::{
    IpAddress, IP_PROTOCOL_TCP, IP_PROTOCOL_UDP, IP_PROTOCOL_ICMP,
};

#[test]
fn test_ip_protocol_tcp() {
    assert_eq!(IP_PROTOCOL_TCP, 6);
}

#[test]
fn test_ip_protocol_udp() {
    assert_eq!(IP_PROTOCOL_UDP, 17);
}

#[test]
fn test_ip_protocol_icmp() {
    assert_eq!(IP_PROTOCOL_ICMP, 1);
}

#[test]
fn test_ip_protocols_unique() {
    assert_ne!(IP_PROTOCOL_TCP, IP_PROTOCOL_UDP);
    assert_ne!(IP_PROTOCOL_TCP, IP_PROTOCOL_ICMP);
    assert_ne!(IP_PROTOCOL_UDP, IP_PROTOCOL_ICMP);
}

#[test]
fn test_ip_address_v4_create() {
    let addr = IpAddress::v4(192, 168, 1, 1);
    assert!(addr.is_ipv4());
    assert!(!addr.is_ipv6());
}

#[test]
fn test_ip_address_v4_variant() {
    let addr = IpAddress::V4([10, 0, 0, 1]);
    assert!(addr.is_ipv4());
    assert!(!addr.is_ipv6());
}

#[test]
fn test_ip_address_v6_variant() {
    let addr = IpAddress::V6([0; 16]);
    assert!(addr.is_ipv6());
    assert!(!addr.is_ipv4());
}

#[test]
fn test_ip_address_unspecified_v4() {
    let addr = IpAddress::v4(0, 0, 0, 0);
    assert!(addr.is_unspecified());
}

#[test]
fn test_ip_address_unspecified_v6() {
    let addr = IpAddress::V6([0; 16]);
    assert!(addr.is_unspecified());
}

#[test]
fn test_ip_address_not_unspecified_v4() {
    let addr = IpAddress::v4(192, 168, 1, 1);
    assert!(!addr.is_unspecified());
}

#[test]
fn test_ip_address_not_unspecified_v6() {
    let addr = IpAddress::V6([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(!addr.is_unspecified());
}

#[test]
fn test_ip_address_loopback_v4() {
    let addr = IpAddress::v4(127, 0, 0, 1);
    assert!(addr.is_loopback());
}

#[test]
fn test_ip_address_loopback_v4_any() {
    let addr = IpAddress::v4(127, 1, 2, 3);
    assert!(addr.is_loopback());
}

#[test]
fn test_ip_address_loopback_v6() {
    let addr = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert!(addr.is_loopback());
}

#[test]
fn test_ip_address_not_loopback_v4() {
    let addr = IpAddress::v4(192, 168, 1, 1);
    assert!(!addr.is_loopback());
}

#[test]
fn test_ip_address_not_loopback_v6() {
    let addr = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    assert!(!addr.is_loopback());
}

#[test]
fn test_ip_address_equality_v4() {
    let addr1 = IpAddress::v4(192, 168, 1, 1);
    let addr2 = IpAddress::v4(192, 168, 1, 1);
    let addr3 = IpAddress::v4(192, 168, 1, 2);
    assert_eq!(addr1, addr2);
    assert_ne!(addr1, addr3);
}

#[test]
fn test_ip_address_equality_v6() {
    let addr1 = IpAddress::V6([1; 16]);
    let addr2 = IpAddress::V6([1; 16]);
    let addr3 = IpAddress::V6([2; 16]);
    assert_eq!(addr1, addr2);
    assert_ne!(addr1, addr3);
}

#[test]
fn test_ip_address_v4_v6_different() {
    let v4 = IpAddress::v4(0, 0, 0, 0);
    let v6 = IpAddress::V6([0; 16]);
    assert_ne!(v4, v6);
}

#[test]
fn test_ip_address_clone() {
    let addr = IpAddress::v4(10, 20, 30, 40);
    let cloned = addr.clone();
    assert_eq!(addr, cloned);
}

#[test]
fn test_ip_address_copy() {
    let addr1 = IpAddress::v4(1, 2, 3, 4);
    let addr2 = addr1;
    assert_eq!(addr1, addr2);
}

#[test]
fn test_ip_address_ordering_v4() {
    let addr1 = IpAddress::v4(192, 168, 1, 1);
    let addr2 = IpAddress::v4(192, 168, 1, 2);
    assert!(addr1 < addr2);
}

#[test]
fn test_ip_address_ordering_v6() {
    let addr1 = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let addr2 = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    assert!(addr1 < addr2);
}

#[test]
fn test_ip_address_common_v4() {
    let localhost = IpAddress::v4(127, 0, 0, 1);
    let private_a = IpAddress::v4(10, 0, 0, 1);
    let private_b = IpAddress::v4(172, 16, 0, 1);
    let private_c = IpAddress::v4(192, 168, 0, 1);

    assert!(localhost.is_loopback());
    assert!(!private_a.is_loopback());
    assert!(!private_b.is_loopback());
    assert!(!private_c.is_loopback());
}

#[test]
fn test_ip_address_broadcast_v4() {
    let broadcast = IpAddress::v4(255, 255, 255, 255);
    assert!(!broadcast.is_unspecified());
    assert!(!broadcast.is_loopback());
}

#[test]
fn test_ip_address_multicast_v4() {
    let multicast = IpAddress::v4(224, 0, 0, 1);
    assert!(!multicast.is_unspecified());
    assert!(!multicast.is_loopback());
}

#[test]
fn test_ip_address_all_variants() {
    let addrs = [
        IpAddress::v4(0, 0, 0, 0),
        IpAddress::v4(127, 0, 0, 1),
        IpAddress::v4(192, 168, 1, 1),
        IpAddress::V6([0; 16]),
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    ];
    for addr in addrs {
        let cloned = addr.clone();
        assert_eq!(addr, cloned);
    }
}

#[test]
fn test_ip_protocol_ordering() {
    assert!(IP_PROTOCOL_ICMP < IP_PROTOCOL_TCP);
    assert!(IP_PROTOCOL_TCP < IP_PROTOCOL_UDP);
}

#[test]
fn test_ip_address_v4_bytes() {
    let addr = IpAddress::V4([192, 168, 1, 100]);
    if let IpAddress::V4(bytes) = addr {
        assert_eq!(bytes[0], 192);
        assert_eq!(bytes[1], 168);
        assert_eq!(bytes[2], 1);
        assert_eq!(bytes[3], 100);
    } else {
        panic!("Expected V4 variant");
    }
}

#[test]
fn test_ip_address_v6_bytes() {
    let addr = IpAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    if let IpAddress::V6(bytes) = addr {
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[15], 1);
    } else {
        panic!("Expected V6 variant");
    }
}

