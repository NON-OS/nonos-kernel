use crate::network::stack::types::{
    TcpSocket, Socket, NetworkStats, ArpEntry, SocketInfo, DhcpLease,
};

#[test]
fn test_tcp_socket_new() {
    let socket1 = TcpSocket::new();
    let socket2 = TcpSocket::new();
    assert_ne!(socket1.connection_id(), socket2.connection_id());
}

#[test]
fn test_tcp_socket_default() {
    let socket = TcpSocket::default();
    assert!(socket.connection_id() > 0);
}

#[test]
fn test_tcp_socket_from_connection() {
    let socket = TcpSocket::from_connection(42);
    assert_eq!(socket.connection_id(), 42);
}

#[test]
fn test_tcp_socket_remote_port() {
    let mut socket = TcpSocket::new();
    socket.remote_port = 443;
    assert_eq!(socket.remote_port, 443);
}

#[test]
fn test_tcp_socket_clone() {
    let socket1 = TcpSocket::new();
    let socket2 = socket1.clone();
    assert_eq!(socket1.connection_id(), socket2.connection_id());
    assert_eq!(socket1.remote_port, socket2.remote_port);
}

#[test]
fn test_tcp_socket_increments_id() {
    let socket1 = TcpSocket::new();
    let socket2 = TcpSocket::new();
    let socket3 = TcpSocket::new();
    assert!(socket1.connection_id() < socket2.connection_id());
    assert!(socket2.connection_id() < socket3.connection_id());
}

#[test]
fn test_socket_new() {
    let socket = Socket::new();
    assert!(socket.connection_id().is_none());
}

#[test]
fn test_socket_default() {
    let socket = Socket::default();
    assert!(socket.connection_id().is_none());
}

#[test]
fn test_socket_for_connection() {
    let socket = Socket::for_connection(123);
    assert_eq!(socket.connection_id(), Some(123));
}

#[test]
fn test_socket_clone() {
    let socket1 = Socket::for_connection(456);
    let socket2 = socket1.clone();
    assert_eq!(socket1.connection_id(), socket2.connection_id());
}

#[test]
fn test_network_stats_default() {
    let stats = NetworkStats::default();
    assert_eq!(stats.tx_packets, 0);
    assert_eq!(stats.rx_packets, 0);
    assert_eq!(stats.tx_bytes, 0);
    assert_eq!(stats.rx_bytes, 0);
}

#[test]
fn test_network_stats_fields() {
    let stats = NetworkStats {
        tx_packets: 1000,
        rx_packets: 2000,
        tx_bytes: 500000,
        rx_bytes: 1000000,
    };
    assert_eq!(stats.tx_packets, 1000);
    assert_eq!(stats.rx_packets, 2000);
    assert_eq!(stats.tx_bytes, 500000);
    assert_eq!(stats.rx_bytes, 1000000);
}

#[test]
fn test_network_stats_clone() {
    let stats = NetworkStats {
        tx_packets: 100,
        rx_packets: 200,
        tx_bytes: 5000,
        rx_bytes: 10000,
    };
    let cloned = stats.clone();
    assert_eq!(stats.tx_packets, cloned.tx_packets);
    assert_eq!(stats.rx_packets, cloned.rx_packets);
    assert_eq!(stats.tx_bytes, cloned.tx_bytes);
    assert_eq!(stats.rx_bytes, cloned.rx_bytes);
}

#[test]
fn test_arp_entry_fields() {
    let entry = ArpEntry {
        ip: [192, 168, 1, 1],
        mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    };
    assert_eq!(entry.ip, [192, 168, 1, 1]);
    assert_eq!(entry.mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
}

#[test]
fn test_arp_entry_clone() {
    let entry = ArpEntry {
        ip: [10, 0, 0, 1],
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    };
    let cloned = entry.clone();
    assert_eq!(entry.ip, cloned.ip);
    assert_eq!(entry.mac, cloned.mac);
}

#[test]
fn test_socket_info_fields() {
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
    assert_eq!(info.id, 1);
    assert!(info.is_tcp);
    assert_eq!(info.local_port, 8080);
    assert_eq!(info.remote_ip, [93, 184, 216, 34]);
    assert_eq!(info.remote_port, 80);
    assert_eq!(info.state, 1);
    assert_eq!(info.rx_available, 1024);
    assert_eq!(info.tx_available, 4096);
    assert!(info.can_recv);
    assert!(info.can_send);
    assert!(!info.has_error);
    assert!(!info.is_closed);
    assert!(!info.peer_closed);
}

#[test]
fn test_socket_info_udp() {
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
    assert!(!info.is_tcp);
    assert_eq!(info.local_port, 53);
}

#[test]
fn test_socket_info_closed() {
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
    assert!(info.is_closed);
    assert!(info.peer_closed);
    assert!(!info.can_recv);
    assert!(!info.can_send);
}

#[test]
fn test_socket_info_with_error() {
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
    assert!(info.has_error);
}

#[test]
fn test_socket_info_clone() {
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
    assert_eq!(info.id, cloned.id);
    assert_eq!(info.is_tcp, cloned.is_tcp);
    assert_eq!(info.local_port, cloned.local_port);
    assert_eq!(info.remote_ip, cloned.remote_ip);
    assert_eq!(info.remote_port, cloned.remote_port);
}

#[test]
fn test_dhcp_lease_fields() {
    let lease = DhcpLease {
        ip: [192, 168, 1, 100],
        gateway: [192, 168, 1, 1],
        dns: [8, 8, 8, 8],
        lease_time: 86400,
    };
    assert_eq!(lease.ip, [192, 168, 1, 100]);
    assert_eq!(lease.gateway, [192, 168, 1, 1]);
    assert_eq!(lease.dns, [8, 8, 8, 8]);
    assert_eq!(lease.lease_time, 86400);
}

#[test]
fn test_dhcp_lease_short_time() {
    let lease = DhcpLease {
        ip: [10, 0, 0, 50],
        gateway: [10, 0, 0, 1],
        dns: [10, 0, 0, 1],
        lease_time: 3600,
    };
    assert_eq!(lease.lease_time, 3600);
}

#[test]
fn test_dhcp_lease_clone() {
    let lease = DhcpLease {
        ip: [172, 16, 0, 100],
        gateway: [172, 16, 0, 1],
        dns: [172, 16, 0, 2],
        lease_time: 43200,
    };
    let cloned = lease.clone();
    assert_eq!(lease.ip, cloned.ip);
    assert_eq!(lease.gateway, cloned.gateway);
    assert_eq!(lease.dns, cloned.dns);
    assert_eq!(lease.lease_time, cloned.lease_time);
}

#[test]
fn test_dhcp_lease_infinite() {
    let lease = DhcpLease {
        ip: [192, 168, 0, 1],
        gateway: [192, 168, 0, 254],
        dns: [1, 1, 1, 1],
        lease_time: 0xFFFFFFFF,
    };
    assert_eq!(lease.lease_time, u32::MAX);
}
