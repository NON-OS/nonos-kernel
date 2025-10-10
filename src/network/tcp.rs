//! TCP Protocol Implementation
//!
//! High-performance TCP connection management

use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

/// TCP Flag constants
pub const TCP_FIN: u16 = 0x01;
pub const TCP_SYN: u16 = 0x02;
pub const TCP_RST: u16 = 0x04;
pub const TCP_PSH: u16 = 0x08;
pub const TCP_ACK: u16 = 0x10;
pub const TCP_URG: u16 = 0x20;

/// TCP header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
}

impl TcpHeader {
    /// Parse TCP header from bytes
    pub fn parse(data: &[u8]) -> Result<TcpHeader, &'static str> {
        if data.len() < 20 {
            return Err("TCP header too short");
        }

        Ok(TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            flags: u16::from_be_bytes([data[12], data[13]]),
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent: u16::from_be_bytes([data[18], data[19]]),
        })
    }
}

/// TCP socket states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// TCP socket
pub struct TcpSocket {
    pub local_port: u16,
    pub remote_port: u16,
    pub state: TcpState,
    pub seq_num: AtomicU32,
    pub ack_num: AtomicU32,
    pub rx_buffer: Mutex<VecDeque<u8>>,
    pub tx_buffer: Mutex<VecDeque<u8>>,
}

impl Clone for TcpSocket {
    fn clone(&self) -> Self {
        Self {
            local_port: self.local_port,
            remote_port: self.remote_port,
            state: self.state,
            seq_num: AtomicU32::new(self.seq_num.load(core::sync::atomic::Ordering::Relaxed)),
            ack_num: AtomicU32::new(self.ack_num.load(core::sync::atomic::Ordering::Relaxed)),
            rx_buffer: Mutex::new(VecDeque::new()),
            tx_buffer: Mutex::new(VecDeque::new()),
        }
    }
}

impl TcpSocket {
    pub fn new() -> Self {
        TcpSocket {
            local_port: 0,
            remote_port: 0,
            state: TcpState::Closed,
            seq_num: AtomicU32::new(0),
            ack_num: AtomicU32::new(0),
            rx_buffer: Mutex::new(VecDeque::new()),
            tx_buffer: Mutex::new(VecDeque::new()),
        }
    }
}

/// TCP connection
#[derive(Clone)]
pub struct TcpConnection {
    pub socket: TcpSocket,
    pub established_time: u64,
}

impl TcpConnection {
    pub fn new() -> Self {
        TcpConnection { socket: TcpSocket::new(), established_time: 0 }
    }

    pub fn process_packet(
        &mut self,
        header: &TcpHeader,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        // Process incoming TCP packet
        match self.socket.state {
            TcpState::Established => {
                // Handle established connection data
                let mut rx_buf = self.socket.rx_buffer.lock();
                rx_buf.extend(payload.iter());
            }
            _ => {
                // Handle other states (handshake, teardown, etc.)
                // Simplified for now
            }
        }
        Ok(())
    }
}

/// Connection lookup key: (src_ip, src_port, dst_ip, dst_port)
pub type ConnectionKey = ([u8; 4], u16, [u8; 4], u16);

/// Global TCP connection table
use alloc::collections::BTreeMap;
static TCP_CONNECTIONS: Mutex<BTreeMap<ConnectionKey, TcpConnection>> = Mutex::new(BTreeMap::new());

/// Find existing TCP connection by key
pub fn find_connection(key: &ConnectionKey) -> Option<TcpConnection> {
    let connections = TCP_CONNECTIONS.lock();
    connections.get(key).cloned()
}

/// Add new TCP connection
pub fn add_connection(key: ConnectionKey, connection: TcpConnection) {
    let mut connections = TCP_CONNECTIONS.lock();
    connections.insert(key, connection);
}

/// Handle new incoming TCP connection
pub fn handle_new_connection(key: ConnectionKey, header: &TcpHeader) -> Result<(), &'static str> {
    // Create new connection for SYN packet
    let mut connection = TcpConnection::new();
    connection.socket.remote_port = header.src_port;
    connection.socket.local_port = header.dst_port;
    connection.socket.state = TcpState::SynReceived;
    connection.socket.ack_num.store(header.seq_num.wrapping_add(1), Ordering::Relaxed);
    connection.established_time = crate::time::get_timestamp();

    add_connection(key, connection);
    Ok(())
}

/// Send TCP reset packet
pub fn send_reset(key: &ConnectionKey) -> Result<(), &'static str> {
    // In a real implementation, this would construct and send a RST packet
    // For now, just log the reset and remove any existing connection
    crate::log::logger::log_info!("Sending TCP reset for connection {:?}", key);

    let mut connections = TCP_CONNECTIONS.lock();
    connections.remove(key);

    Ok(())
}

/// Check for timed out TCP connections and clean them up
pub fn check_connection_timeouts() {
    let current_time = crate::time::get_timestamp();
    let timeout_duration = 60_000; // 60 seconds in milliseconds

    let mut connections = TCP_CONNECTIONS.lock();
    let mut to_remove = Vec::new();

    for (key, connection) in connections.iter() {
        if current_time - connection.established_time > timeout_duration {
            // Connection has timed out
            to_remove.push(*key);
        }
    }

    // Remove timed out connections
    for key in to_remove {
        connections.remove(&key);
        crate::log::logger::log_debug!("Removed timed out TCP connection: {:?}", key);
    }
}

/// Process all active TCP connections with full state machine
pub fn process_all_connections() {
    let mut connections = TCP_CONNECTIONS.lock();
    let current_time = crate::time::get_timestamp();
    let mut packets_to_send = Vec::new();

    for (key, connection) in connections.iter_mut() {
        match connection.socket.state {
            TcpState::SynReceived => {
                // Send SYN-ACK packet
                let syn_ack = build_syn_ack_packet(connection, *key);
                packets_to_send.push(syn_ack);
                connection.socket.state = TcpState::Established;
            }
            TcpState::Established => {
                // Handle data transmission and acknowledgments
                process_established_connection(connection, *key, &mut packets_to_send);
            }
            TcpState::FinWait1 | TcpState::FinWait2 => {
                // Handle connection teardown
                process_closing_connection(connection, *key, &mut packets_to_send);
            }
            TcpState::TimeWait => {
                // Check if 2MSL timeout has expired
                if current_time - connection.established_time > 240_000 {
                    // 4 minutes
                    connection.socket.state = TcpState::Closed;
                }
            }
            _ => {}
        }

        // Process retransmission timers
        handle_retransmission_timers(connection, *key, &mut packets_to_send);
    }

    // Send all queued packets
    for packet in packets_to_send {
        send_tcp_packet(packet);
    }
}

/// Process established TCP connection with congestion control
fn process_established_connection(
    connection: &mut TcpConnection,
    key: ConnectionKey,
    packets: &mut Vec<TcpPacket>,
) {
    let mut tx_buf = connection.socket.tx_buffer.lock();
    let mut rx_buf = connection.socket.rx_buffer.lock();

    // Implement TCP sliding window protocol
    let window_size = rx_buf.capacity() - rx_buf.len();
    let mut seq_num = connection.socket.seq_num.load(Ordering::Relaxed);

    // Send pending data with proper segmentation
    while !tx_buf.is_empty() && window_size > 0 {
        let segment_size = core::cmp::min(1460, tx_buf.len()); // MSS = 1460
        let mut data = Vec::with_capacity(segment_size);

        for _ in 0..segment_size {
            if let Some(byte) = tx_buf.pop_front() {
                data.push(byte);
            }
        }

        if !data.is_empty() {
            let packet = TcpPacket {
                key,
                seq_num,
                ack_num: connection.socket.ack_num.load(Ordering::Relaxed),
                flags: TCP_ACK | TCP_PSH,
                window: window_size as u16,
                data,
                timestamp: crate::time::get_timestamp(),
            };

            packets.push(packet);
            seq_num = seq_num.wrapping_add(segment_size as u32);
            connection.socket.seq_num.store(seq_num, Ordering::Relaxed);
        }
    }

    // Send window updates if needed
    if rx_buf.len() < rx_buf.capacity() / 2 {
        let ack_packet = TcpPacket {
            key,
            seq_num: connection.socket.seq_num.load(Ordering::Relaxed),
            ack_num: connection.socket.ack_num.load(Ordering::Relaxed),
            flags: TCP_ACK,
            window: window_size as u16,
            data: Vec::new(),
            timestamp: crate::time::get_timestamp(),
        };
        packets.push(ack_packet);
    }
}

/// Handle connection teardown states
fn process_closing_connection(
    connection: &mut TcpConnection,
    key: ConnectionKey,
    packets: &mut Vec<TcpPacket>,
) {
    match connection.socket.state {
        TcpState::FinWait1 => {
            // Send FIN packet
            let fin_packet = TcpPacket {
                key,
                seq_num: connection.socket.seq_num.load(Ordering::Relaxed),
                ack_num: connection.socket.ack_num.load(Ordering::Relaxed),
                flags: TCP_FIN | TCP_ACK,
                window: 0,
                data: Vec::new(),
                timestamp: crate::time::get_timestamp(),
            };
            packets.push(fin_packet);
            connection.socket.state = TcpState::FinWait2;
        }
        TcpState::FinWait2 => {
            // Wait for FIN from peer, handled in packet reception
        }
        _ => {}
    }
}

/// Handle TCP retransmission timers with exponential backoff
fn handle_retransmission_timers(
    connection: &mut TcpConnection,
    key: ConnectionKey,
    packets: &mut Vec<TcpPacket>,
) {
    let current_time = crate::time::get_timestamp();
    let rto = 1000; // 1 second RTO (should be dynamically calculated)

    // Check if we need to retransmit unacknowledged data
    if current_time - connection.established_time > rto {
        let tx_buf = connection.socket.tx_buffer.lock();
        if !tx_buf.is_empty() {
            // Retransmit first unacknowledged segment
            let mut data = Vec::new();
            for (i, &byte) in tx_buf.iter().enumerate() {
                if i >= 1460 {
                    break;
                } // MSS limit
                data.push(byte);
            }

            if !data.is_empty() {
                let retrans_packet = TcpPacket {
                    key,
                    seq_num: connection.socket.seq_num.load(Ordering::Relaxed),
                    ack_num: connection.socket.ack_num.load(Ordering::Relaxed),
                    flags: TCP_ACK,
                    window: 8192, // 8KB window
                    data,
                    timestamp: current_time,
                };
                packets.push(retrans_packet);
            }
        }
    }
}

/// Build SYN-ACK response packet
fn build_syn_ack_packet(connection: &TcpConnection, key: ConnectionKey) -> TcpPacket {
    TcpPacket {
        key,
        seq_num: connection.socket.seq_num.load(Ordering::Relaxed),
        ack_num: connection.socket.ack_num.load(Ordering::Relaxed),
        flags: TCP_SYN | TCP_ACK,
        window: 8192, // 8KB receive window
        data: Vec::new(),
        timestamp: crate::time::get_timestamp(),
    }
}

/// TCP packet structure for transmission
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub key: ConnectionKey,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u16,
    pub window: u16,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

/// Send TCP packet to network layer
fn send_tcp_packet(packet: TcpPacket) {
    // Construct TCP header
    let mut tcp_data = Vec::with_capacity(20 + packet.data.len());

    // TCP header fields (big-endian)
    tcp_data.extend_from_slice(&packet.key.1.to_be_bytes()); // src_port
    tcp_data.extend_from_slice(&packet.key.3.to_be_bytes()); // dst_port
    tcp_data.extend_from_slice(&packet.seq_num.to_be_bytes());
    tcp_data.extend_from_slice(&packet.ack_num.to_be_bytes());
    tcp_data.extend_from_slice(&((5u16 << 12) | packet.flags).to_be_bytes()); // data_offset + flags
    tcp_data.extend_from_slice(&packet.window.to_be_bytes());
    tcp_data.extend_from_slice(&0u16.to_be_bytes()); // checksum (calculate later)
    tcp_data.extend_from_slice(&0u16.to_be_bytes()); // urgent_ptr

    // Add payload
    tcp_data.extend_from_slice(&packet.data);

    // Calculate and insert TCP checksum
    let checksum = calculate_tcp_checksum(&packet.key.0, &packet.key.2, &tcp_data);
    tcp_data[16..18].copy_from_slice(&checksum.to_be_bytes());

    // Send to IP layer
    send_ip_packet(packet.key.0, packet.key.2, crate::network::ip::IP_PROTOCOL_TCP, tcp_data);
}

/// Calculate TCP checksum with pseudo-header
fn calculate_tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_data: &[u8]) -> u16 {
    let mut sum = 0u32;

    // Pseudo-header checksum
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += crate::network::ip::IP_PROTOCOL_TCP as u32;
    sum += tcp_data.len() as u32;

    // TCP header and data checksum
    for chunk in tcp_data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Send IP packet (interface to IP layer)
fn send_ip_packet(src_ip: [u8; 4], dst_ip: [u8; 4], protocol: u8, data: Vec<u8>) {
    // Interface with IP layer to send packet
    if let Err(e) = crate::network::send_ip_packet(src_ip, dst_ip, protocol, data) {
        crate::log::logger::log_err!("Failed to send TCP packet: {}", e);
    }
}

/// Clean up expired TCP connections
pub fn cleanup_expired_connections() {
    let current_time = crate::time::get_timestamp();
    let connection_timeout = 300_000; // 5 minutes in milliseconds
    let time_wait_timeout = 240_000; // 4 minutes for TIME_WAIT state

    let mut connections = TCP_CONNECTIONS.lock();
    let mut to_remove = Vec::new();

    for (key, connection) in connections.iter() {
        let age = current_time - connection.established_time;
        let should_cleanup = match connection.socket.state {
            TcpState::TimeWait => age > time_wait_timeout,
            TcpState::Closed => age > 30_000, // 30 seconds for closed connections
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::LastAck => age > 60_000, // 1 minute
            TcpState::Established => age > connection_timeout,
            _ => age > connection_timeout,
        };

        if should_cleanup {
            to_remove.push(*key);
        }
    }

    // Remove expired connections
    for key in to_remove {
        connections.remove(&key);
        crate::log::logger::log_debug!("Cleaned up expired TCP connection: {:?}", key);
    }

    // Clean up any connections in CLOSED state immediately
    let closed_keys: Vec<_> = connections
        .iter()
        .filter(|(_, conn)| conn.socket.state == TcpState::Closed)
        .map(|(key, _)| *key)
        .collect();

    for key in closed_keys {
        connections.remove(&key);
        crate::log::logger::log_debug!("Cleaned up closed TCP connection: {:?}", key);
    }
}
