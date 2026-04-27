// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Network stack type tests

use crate::network::stack::types::{
    ArpEntry, DhcpLease, NetworkStats, Socket, SocketInfo, TcpSocket,
};
use crate::test::framework::TestResult;

pub(crate) fn test_tcp_socket_new() -> TestResult {
    let socket1 = TcpSocket::new();
    let socket2 = TcpSocket::new();
    if socket1.connection_id() == socket2.connection_id() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_socket_default() -> TestResult {
    let socket = TcpSocket::default();
    if socket.connection_id() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_socket_from_connection() -> TestResult {
    let socket = TcpSocket::from_connection(42);
    if socket.connection_id() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_socket_remote_port() -> TestResult {
    let mut socket = TcpSocket::new();
    socket.remote_port = 443;
    if socket.remote_port != 443 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_socket_clone() -> TestResult {
    let socket1 = TcpSocket::new();
    let socket2 = socket1.clone();
    if socket1.connection_id() != socket2.connection_id() {
        return TestResult::Fail;
    }
    if socket1.remote_port != socket2.remote_port {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_socket_increments_id() -> TestResult {
    let socket1 = TcpSocket::new();
    let socket2 = TcpSocket::new();
    let socket3 = TcpSocket::new();
    if socket1.connection_id() >= socket2.connection_id() {
        return TestResult::Fail;
    }
    if socket2.connection_id() >= socket3.connection_id() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_new() -> TestResult {
    let socket = Socket::new();
    if socket.connection_id().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_default() -> TestResult {
    let socket = Socket::default();
    if socket.connection_id().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_for_connection() -> TestResult {
    let socket = Socket::for_connection(123);
    if socket.connection_id() != Some(123) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_clone() -> TestResult {
    let socket1 = Socket::for_connection(456);
    let socket2 = socket1.clone();
    if socket1.connection_id() != socket2.connection_id() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_stats_default() -> TestResult {
    let stats = NetworkStats::default();
    if stats.tx_packets != 0 {
        return TestResult::Fail;
    }
    if stats.rx_packets != 0 {
        return TestResult::Fail;
    }
    if stats.tx_bytes != 0 {
        return TestResult::Fail;
    }
    if stats.rx_bytes != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_stats_fields() -> TestResult {
    let stats =
        NetworkStats { tx_packets: 1000, rx_packets: 2000, tx_bytes: 500000, rx_bytes: 1000000 };
    if stats.tx_packets != 1000 {
        return TestResult::Fail;
    }
    if stats.rx_packets != 2000 {
        return TestResult::Fail;
    }
    if stats.tx_bytes != 500000 {
        return TestResult::Fail;
    }
    if stats.rx_bytes != 1000000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_network_stats_clone() -> TestResult {
    let stats = NetworkStats { tx_packets: 100, rx_packets: 200, tx_bytes: 5000, rx_bytes: 10000 };
    let cloned = stats.clone();
    if stats.tx_packets != cloned.tx_packets {
        return TestResult::Fail;
    }
    if stats.rx_packets != cloned.rx_packets {
        return TestResult::Fail;
    }
    if stats.tx_bytes != cloned.tx_bytes {
        return TestResult::Fail;
    }
    if stats.rx_bytes != cloned.rx_bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_arp_entry_fields() -> TestResult {
    let entry = ArpEntry { ip: [192, 168, 1, 1], mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] };
    if entry.ip != [192, 168, 1, 1] {
        return TestResult::Fail;
    }
    if entry.mac != [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_arp_entry_clone() -> TestResult {
    let entry = ArpEntry { ip: [10, 0, 0, 1], mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55] };
    let cloned = entry.clone();
    if entry.ip != cloned.ip {
        return TestResult::Fail;
    }
    if entry.mac != cloned.mac {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_info_fields() -> TestResult {
    let info = SocketInfo {
        id: 1,
        is_tcp: true,
        local_port: 8080,
        remote_ip: [93, 184, 216, 34],
        remote_port: 80,
        state: 1,
        rx_available: 1024,
        tx_available: 4096,
        can_recv: true,
        can_send: true,
        has_error: false,
        is_closed: false,
        peer_closed: false,
    };
    if info.id != 1 {
        return TestResult::Fail;
    }
    if !info.is_tcp {
        return TestResult::Fail;
    }
    if info.local_port != 8080 {
        return TestResult::Fail;
    }
    if info.remote_ip != [93, 184, 216, 34] {
        return TestResult::Fail;
    }
    if info.remote_port != 80 {
        return TestResult::Fail;
    }
    if info.state != 1 {
        return TestResult::Fail;
    }
    if info.rx_available != 1024 {
        return TestResult::Fail;
    }
    if info.tx_available != 4096 {
        return TestResult::Fail;
    }
    if !info.can_recv {
        return TestResult::Fail;
    }
    if !info.can_send {
        return TestResult::Fail;
    }
    if info.has_error {
        return TestResult::Fail;
    }
    if info.is_closed {
        return TestResult::Fail;
    }
    if info.peer_closed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_info_udp() -> TestResult {
    let info = SocketInfo {
        id: 2,
        is_tcp: false,
        local_port: 53,
        remote_ip: [8, 8, 8, 8],
        remote_port: 53,
        state: 0,
        rx_available: 512,
        tx_available: 512,
        can_recv: true,
        can_send: true,
        has_error: false,
        is_closed: false,
        peer_closed: false,
    };
    if info.is_tcp {
        return TestResult::Fail;
    }
    if info.local_port != 53 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_info_closed() -> TestResult {
    let info = SocketInfo {
        id: 3,
        is_tcp: true,
        local_port: 0,
        remote_ip: [0; 4],
        remote_port: 0,
        state: 0,
        rx_available: 0,
        tx_available: 0,
        can_recv: false,
        can_send: false,
        has_error: false,
        is_closed: true,
        peer_closed: true,
    };
    if !info.is_closed {
        return TestResult::Fail;
    }
    if !info.peer_closed {
        return TestResult::Fail;
    }
    if info.can_recv {
        return TestResult::Fail;
    }
    if info.can_send {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_info_with_error() -> TestResult {
    let info = SocketInfo {
        id: 4,
        is_tcp: true,
        local_port: 443,
        remote_ip: [0; 4],
        remote_port: 0,
        state: 0,
        rx_available: 0,
        tx_available: 0,
        can_recv: false,
        can_send: false,
        has_error: true,
        is_closed: true,
        peer_closed: false,
    };
    if !info.has_error {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socket_info_clone() -> TestResult {
    let info = SocketInfo {
        id: 5,
        is_tcp: true,
        local_port: 22,
        remote_ip: [192, 168, 1, 100],
        remote_port: 22,
        state: 3,
        rx_available: 2048,
        tx_available: 8192,
        can_recv: true,
        can_send: true,
        has_error: false,
        is_closed: false,
        peer_closed: false,
    };
    let cloned = info.clone();
    if info.id != cloned.id {
        return TestResult::Fail;
    }
    if info.is_tcp != cloned.is_tcp {
        return TestResult::Fail;
    }
    if info.local_port != cloned.local_port {
        return TestResult::Fail;
    }
    if info.remote_ip != cloned.remote_ip {
        return TestResult::Fail;
    }
    if info.remote_port != cloned.remote_port {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dhcp_lease_fields() -> TestResult {
    let lease = DhcpLease {
        ip: [192, 168, 1, 100],
        gateway: [192, 168, 1, 1],
        dns: [8, 8, 8, 8],
        lease_time: 86400,
    };
    if lease.ip != [192, 168, 1, 100] {
        return TestResult::Fail;
    }
    if lease.gateway != [192, 168, 1, 1] {
        return TestResult::Fail;
    }
    if lease.dns != [8, 8, 8, 8] {
        return TestResult::Fail;
    }
    if lease.lease_time != 86400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dhcp_lease_short_time() -> TestResult {
    let lease = DhcpLease {
        ip: [10, 0, 0, 50],
        gateway: [10, 0, 0, 1],
        dns: [10, 0, 0, 1],
        lease_time: 3600,
    };
    if lease.lease_time != 3600 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dhcp_lease_clone() -> TestResult {
    let lease = DhcpLease {
        ip: [172, 16, 0, 100],
        gateway: [172, 16, 0, 1],
        dns: [172, 16, 0, 2],
        lease_time: 43200,
    };
    let cloned = lease.clone();
    if lease.ip != cloned.ip {
        return TestResult::Fail;
    }
    if lease.gateway != cloned.gateway {
        return TestResult::Fail;
    }
    if lease.dns != cloned.dns {
        return TestResult::Fail;
    }
    if lease.lease_time != cloned.lease_time {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dhcp_lease_infinite() -> TestResult {
    let lease = DhcpLease {
        ip: [192, 168, 0, 1],
        gateway: [192, 168, 0, 254],
        dns: [1, 1, 1, 1],
        lease_time: 0xFFFFFFFF,
    };
    if lease.lease_time != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}
