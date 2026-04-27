// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// TCP protocol type tests

use crate::network::tcp::types::{
    TcpConnection, TcpHeader, TcpState, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
};
use crate::test::framework::TestResult;

pub(crate) fn test_tcp_syn_constant() -> TestResult {
    if TCP_SYN != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_ack_constant() -> TestResult {
    if TCP_ACK != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_fin_constant() -> TestResult {
    if TCP_FIN != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_rst_constant() -> TestResult {
    if TCP_RST != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_psh_constant() -> TestResult {
    if TCP_PSH != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_flags_unique() -> TestResult {
    if TCP_SYN == TCP_ACK {
        return TestResult::Fail;
    }
    if TCP_SYN == TCP_FIN {
        return TestResult::Fail;
    }
    if TCP_ACK == TCP_FIN {
        return TestResult::Fail;
    }
    if TCP_RST == TCP_PSH {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_flags_combinable() -> TestResult {
    let syn_ack = TCP_SYN | TCP_ACK;
    if syn_ack != 0x12 {
        return TestResult::Fail;
    }
    if (syn_ack & TCP_SYN) == 0 {
        return TestResult::Fail;
    }
    if (syn_ack & TCP_ACK) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_closed() -> TestResult {
    let state = TcpState::Closed;
    if !state.is_closed() {
        return TestResult::Fail;
    }
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_listen() -> TestResult {
    let state = TcpState::Listen;
    if state.is_closed() {
        return TestResult::Fail;
    }
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_syn_sent() -> TestResult {
    let state = TcpState::SynSent;
    if state.is_closed() {
        return TestResult::Fail;
    }
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_syn_received() -> TestResult {
    let state = TcpState::SynReceived;
    if state.is_closed() {
        return TestResult::Fail;
    }
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_established() -> TestResult {
    let state = TcpState::Established;
    if !state.is_established() {
        return TestResult::Fail;
    }
    if state.is_closed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_fin_wait1() -> TestResult {
    let state = TcpState::FinWait1;
    if state.is_established() {
        return TestResult::Fail;
    }
    if state.is_closed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_fin_wait2() -> TestResult {
    let state = TcpState::FinWait2;
    if state.is_established() {
        return TestResult::Fail;
    }
    if state.is_closed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_close_wait() -> TestResult {
    let state = TcpState::CloseWait;
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_closing() -> TestResult {
    let state = TcpState::Closing;
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_last_ack() -> TestResult {
    let state = TcpState::LastAck;
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_time_wait() -> TestResult {
    let state = TcpState::TimeWait;
    if state.is_established() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_equality() -> TestResult {
    if TcpState::Closed != TcpState::Closed {
        return TestResult::Fail;
    }
    if TcpState::Established != TcpState::Established {
        return TestResult::Fail;
    }
    if TcpState::Closed == TcpState::Established {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_clone() -> TestResult {
    let state = TcpState::Established;
    let cloned = state.clone();
    if state != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_copy() -> TestResult {
    let state1 = TcpState::Listen;
    let state2 = state1;
    if state1 != state2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_min_size() -> TestResult {
    if TcpHeader::MIN_SIZE != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_is_syn() -> TestResult {
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
    if !header.is_syn() {
        return TestResult::Fail;
    }
    if header.is_ack() {
        return TestResult::Fail;
    }
    if header.is_fin() {
        return TestResult::Fail;
    }
    if header.is_rst() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_is_ack() -> TestResult {
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
    if !header.is_ack() {
        return TestResult::Fail;
    }
    if header.is_syn() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_is_fin() -> TestResult {
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
    if !header.is_fin() {
        return TestResult::Fail;
    }
    if !header.is_ack() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_is_rst() -> TestResult {
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
    if !header.is_rst() {
        return TestResult::Fail;
    }
    if header.is_syn() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_syn_ack() -> TestResult {
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
    if !header.is_syn() {
        return TestResult::Fail;
    }
    if !header.is_ack() {
        return TestResult::Fail;
    }
    if header.is_fin() {
        return TestResult::Fail;
    }
    if header.is_rst() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_clone() -> TestResult {
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
    if header.src_port != cloned.src_port {
        return TestResult::Fail;
    }
    if header.dst_port != cloned.dst_port {
        return TestResult::Fail;
    }
    if header.seq_num != cloned.seq_num {
        return TestResult::Fail;
    }
    if header.ack_num != cloned.ack_num {
        return TestResult::Fail;
    }
    if header.flags != cloned.flags {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_max_ports() -> TestResult {
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
    if header.src_port != 65535 {
        return TestResult::Fail;
    }
    if header.dst_port != 65535 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_connection_new() -> TestResult {
    let conn = TcpConnection::new();
    if conn.state != TcpState::Closed {
        return TestResult::Fail;
    }
    if conn.local_port != 0 {
        return TestResult::Fail;
    }
    if conn.remote_port != 0 {
        return TestResult::Fail;
    }
    if conn.remote_addr != [0; 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_connection_default() -> TestResult {
    let conn = TcpConnection::default();
    if conn.state != TcpState::Closed {
        return TestResult::Fail;
    }
    if conn.local_port != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_connection_fields() -> TestResult {
    let conn = TcpConnection {
        state: TcpState::Established,
        local_port: 8080,
        remote_port: 443,
        remote_addr: [93, 184, 216, 34],
    };
    if conn.state != TcpState::Established {
        return TestResult::Fail;
    }
    if conn.local_port != 8080 {
        return TestResult::Fail;
    }
    if conn.remote_port != 443 {
        return TestResult::Fail;
    }
    if conn.remote_addr != [93, 184, 216, 34] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_connection_clone() -> TestResult {
    let conn = TcpConnection {
        state: TcpState::SynSent,
        local_port: 54321,
        remote_port: 80,
        remote_addr: [192, 168, 1, 1],
    };
    let cloned = conn.clone();
    if conn.state != cloned.state {
        return TestResult::Fail;
    }
    if conn.local_port != cloned.local_port {
        return TestResult::Fail;
    }
    if conn.remote_port != cloned.remote_port {
        return TestResult::Fail;
    }
    if conn.remote_addr != cloned.remote_addr {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_state_all_variants() -> TestResult {
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
        if state != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_header_all_flags_combined() -> TestResult {
    let all_flags = TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST | TCP_PSH;
    if all_flags != 0x1F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tcp_connection_localhost() -> TestResult {
    let conn = TcpConnection {
        state: TcpState::Established,
        local_port: 8080,
        remote_port: 8080,
        remote_addr: [127, 0, 0, 1],
    };
    if conn.remote_addr[0] != 127 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
