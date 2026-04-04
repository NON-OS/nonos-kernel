// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::tcp::types::{
    TcpState, TcpHeader, TcpConnection,
    TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST, TCP_PSH,
};

#[test]
fn test_tcp_syn_constant() {
    assert_eq!(TCP_SYN, 0x02);
}

#[test]
fn test_tcp_ack_constant() {
    assert_eq!(TCP_ACK, 0x10);
}

#[test]
fn test_tcp_fin_constant() {
    assert_eq!(TCP_FIN, 0x01);
}

#[test]
fn test_tcp_rst_constant() {
    assert_eq!(TCP_RST, 0x04);
}

#[test]
fn test_tcp_psh_constant() {
    assert_eq!(TCP_PSH, 0x08);
}

#[test]
fn test_tcp_flags_unique() {
    assert_ne!(TCP_SYN, TCP_ACK);
    assert_ne!(TCP_SYN, TCP_FIN);
    assert_ne!(TCP_ACK, TCP_FIN);
    assert_ne!(TCP_RST, TCP_PSH);
}

#[test]
fn test_tcp_flags_combinable() {
    let syn_ack = TCP_SYN | TCP_ACK;
    assert_eq!(syn_ack, 0x12);
    assert!((syn_ack & TCP_SYN) != 0);
    assert!((syn_ack & TCP_ACK) != 0);
}

#[test]
fn test_tcp_state_closed() {
    let state = TcpState::Closed;
    assert!(state.is_closed());
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_listen() {
    let state = TcpState::Listen;
    assert!(!state.is_closed());
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_syn_sent() {
    let state = TcpState::SynSent;
    assert!(!state.is_closed());
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_syn_received() {
    let state = TcpState::SynReceived;
    assert!(!state.is_closed());
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_established() {
    let state = TcpState::Established;
    assert!(state.is_established());
    assert!(!state.is_closed());
}

#[test]
fn test_tcp_state_fin_wait1() {
    let state = TcpState::FinWait1;
    assert!(!state.is_established());
    assert!(!state.is_closed());
}

#[test]
fn test_tcp_state_fin_wait2() {
    let state = TcpState::FinWait2;
    assert!(!state.is_established());
    assert!(!state.is_closed());
}

#[test]
fn test_tcp_state_close_wait() {
    let state = TcpState::CloseWait;
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_closing() {
    let state = TcpState::Closing;
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_last_ack() {
    let state = TcpState::LastAck;
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_time_wait() {
    let state = TcpState::TimeWait;
    assert!(!state.is_established());
}

#[test]
fn test_tcp_state_equality() {
    assert_eq!(TcpState::Closed, TcpState::Closed);
    assert_eq!(TcpState::Established, TcpState::Established);
    assert_ne!(TcpState::Closed, TcpState::Established);
}

#[test]
fn test_tcp_state_clone() {
    let state = TcpState::Established;
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
fn test_tcp_state_copy() {
    let state1 = TcpState::Listen;
    let state2 = state1;
    assert_eq!(state1, state2);
}

#[test]
fn test_tcp_header_min_size() {
    assert_eq!(TcpHeader::MIN_SIZE, 20);
}

#[test]
fn test_tcp_header_is_syn() {
    let header = TcpHeader {
        src_port: 12345,
        dst_port: 80,
        seq_num: 0,
        ack_num: 0,
        data_offset: 5,
        flags: TCP_SYN,
        window: 65535,
        checksum: 0,
        urgent_ptr: 0,
    };
    assert!(header.is_syn());
    assert!(!header.is_ack());
    assert!(!header.is_fin());
    assert!(!header.is_rst());
}

#[test]
fn test_tcp_header_is_ack() {
    let header = TcpHeader {
        src_port: 80,
        dst_port: 12345,
        seq_num: 1,
        ack_num: 1,
        data_offset: 5,
        flags: TCP_ACK,
        window: 65535,
        checksum: 0,
        urgent_ptr: 0,
    };
    assert!(header.is_ack());
    assert!(!header.is_syn());
}

#[test]
fn test_tcp_header_is_fin() {
    let header = TcpHeader {
        src_port: 12345,
        dst_port: 80,
        seq_num: 100,
        ack_num: 100,
        data_offset: 5,
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        checksum: 0,
        urgent_ptr: 0,
    };
    assert!(header.is_fin());
    assert!(header.is_ack());
}

#[test]
fn test_tcp_header_is_rst() {
    let header = TcpHeader {
        src_port: 80,
        dst_port: 12345,
        seq_num: 0,
        ack_num: 0,
        data_offset: 5,
        flags: TCP_RST,
        window: 0,
        checksum: 0,
        urgent_ptr: 0,
    };
    assert!(header.is_rst());
    assert!(!header.is_syn());
}

#[test]
fn test_tcp_header_syn_ack() {
    let header = TcpHeader {
        src_port: 80,
        dst_port: 12345,
        seq_num: 1000,
        ack_num: 1,
        data_offset: 5,
        flags: TCP_SYN | TCP_ACK,
        window: 65535,
        checksum: 0,
        urgent_ptr: 0,
    };
    assert!(header.is_syn());
    assert!(header.is_ack());
    assert!(!header.is_fin());
    assert!(!header.is_rst());
}

#[test]
fn test_tcp_header_clone() {
    let header = TcpHeader {
        src_port: 443,
        dst_port: 54321,
        seq_num: 12345678,
        ack_num: 87654321,
        data_offset: 5,
        flags: TCP_ACK | TCP_PSH,
        window: 32768,
        checksum: 0xABCD,
        urgent_ptr: 0,
    };
    let cloned = header.clone();
    assert_eq!(header.src_port, cloned.src_port);
    assert_eq!(header.dst_port, cloned.dst_port);
    assert_eq!(header.seq_num, cloned.seq_num);
    assert_eq!(header.ack_num, cloned.ack_num);
    assert_eq!(header.flags, cloned.flags);
}

#[test]
fn test_tcp_header_max_ports() {
    let header = TcpHeader {
        src_port: 65535,
        dst_port: 65535,
        seq_num: u32::MAX,
        ack_num: u32::MAX,
        data_offset: 15,
        flags: 0xFF,
        window: u16::MAX,
        checksum: u16::MAX,
        urgent_ptr: u16::MAX,
    };
    assert_eq!(header.src_port, 65535);
    assert_eq!(header.dst_port, 65535);
}

#[test]
fn test_tcp_connection_new() {
    let conn = TcpConnection::new();
    assert_eq!(conn.state, TcpState::Closed);
    assert_eq!(conn.local_port, 0);
    assert_eq!(conn.remote_port, 0);
    assert_eq!(conn.remote_addr, [0; 4]);
}

#[test]
fn test_tcp_connection_default() {
    let conn = TcpConnection::default();
    assert_eq!(conn.state, TcpState::Closed);
    assert_eq!(conn.local_port, 0);
}

#[test]
fn test_tcp_connection_fields() {
    let conn = TcpConnection {
        state: TcpState::Established,
        local_port: 8080,
        remote_port: 443,
        remote_addr: [93, 184, 216, 34],
    };
    assert_eq!(conn.state, TcpState::Established);
    assert_eq!(conn.local_port, 8080);
    assert_eq!(conn.remote_port, 443);
    assert_eq!(conn.remote_addr, [93, 184, 216, 34]);
}

#[test]
fn test_tcp_connection_clone() {
    let conn = TcpConnection {
        state: TcpState::SynSent,
        local_port: 54321,
        remote_port: 80,
        remote_addr: [192, 168, 1, 1],
    };
    let cloned = conn.clone();
    assert_eq!(conn.state, cloned.state);
    assert_eq!(conn.local_port, cloned.local_port);
    assert_eq!(conn.remote_port, cloned.remote_port);
    assert_eq!(conn.remote_addr, cloned.remote_addr);
}

#[test]
fn test_tcp_state_all_variants() {
    let states = [
        TcpState::Closed,
        TcpState::Listen,
        TcpState::SynSent,
        TcpState::SynReceived,
        TcpState::Established,
        TcpState::FinWait1,
        TcpState::FinWait2,
        TcpState::CloseWait,
        TcpState::Closing,
        TcpState::LastAck,
        TcpState::TimeWait,
    ];
    for state in states {
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }
}

#[test]
fn test_tcp_header_all_flags_combined() {
    let all_flags = TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST | TCP_PSH;
    assert_eq!(all_flags, 0x1F);
}

#[test]
fn test_tcp_connection_localhost() {
    let conn = TcpConnection {
        state: TcpState::Established,
        local_port: 8080,
        remote_port: 8080,
        remote_addr: [127, 0, 0, 1],
    };
    assert_eq!(conn.remote_addr[0], 127);
}

