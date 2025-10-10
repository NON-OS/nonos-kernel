//! UDP Protocol Implementation
//!
//! High-performance UDP datagram processing

use alloc::{collections::VecDeque, vec::Vec};
use spin::Mutex;

/// UDP header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse UDP header from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("UDP header too short");
        }

        Ok(UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }
}

/// UDP socket
pub struct UdpSocket {
    pub local_port: u16,
    pub remote_port: u16,
    pub rx_buffer: Mutex<VecDeque<Vec<u8>>>,
    pub tx_buffer: Mutex<VecDeque<Vec<u8>>>,
}

impl Clone for UdpSocket {
    fn clone(&self) -> Self {
        Self {
            local_port: self.local_port,
            remote_port: self.remote_port,
            rx_buffer: Mutex::new(VecDeque::new()),
            tx_buffer: Mutex::new(VecDeque::new()),
        }
    }
}

impl UdpSocket {
    pub fn new() -> Self {
        UdpSocket {
            local_port: 0,
            remote_port: 0,
            rx_buffer: Mutex::new(VecDeque::new()),
            tx_buffer: Mutex::new(VecDeque::new()),
        }
    }
}

/// UDP datagram
pub struct UdpDatagram {
    pub header: UdpHeader,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    pub fn new(src_port: u16, dst_port: u16, payload: Vec<u8>) -> Self {
        let header = UdpHeader {
            src_port,
            dst_port,
            length: (8 + payload.len()) as u16,
            checksum: 0, // Would calculate proper checksum
        };

        UdpDatagram { header, payload }
    }
}

/// Global UDP socket registry
use alloc::collections::BTreeMap;
static UDP_SOCKETS: Mutex<BTreeMap<u16, UdpSocket>> = Mutex::new(BTreeMap::new());

/// Find UDP socket by port number
pub fn find_socket(port: u16) -> Option<UdpSocket> {
    let sockets = UDP_SOCKETS.lock();
    sockets.get(&port).cloned()
}

/// Bind UDP socket to a port
pub fn bind_socket(port: u16, socket: UdpSocket) -> Result<(), &'static str> {
    let mut sockets = UDP_SOCKETS.lock();
    if sockets.contains_key(&port) {
        return Err("Port already in use");
    }
    sockets.insert(port, socket);
    Ok(())
}

/// Remove UDP socket from registry
pub fn unbind_socket(port: u16) -> Option<UdpSocket> {
    let mut sockets = UDP_SOCKETS.lock();
    sockets.remove(&port)
}

/// Process all UDP sockets for pending operations
pub fn process_all_sockets() {
    let sockets = UDP_SOCKETS.lock();

    for (port, socket) in sockets.iter() {
        // Process pending transmit data
        let mut tx_buf = socket.tx_buffer.lock();
        while let Some(packet) = tx_buf.pop_front() {
            // Send UDP packet
            if let Err(e) = send_udp_datagram(*port, 0, packet) {
                crate::log::logger::log_warn!("Failed to send UDP packet on port {}: {}", port, e);
                break; // Stop processing on error
            }
        }

        // Process received data buffers
        let rx_buf = socket.rx_buffer.lock();
        if !rx_buf.is_empty() {
            crate::log::logger::log_debug!(
                "UDP port {} has {} packets in receive buffer",
                port,
                rx_buf.len()
            );
        }
    }
}

/// Send UDP datagram
fn send_udp_datagram(src_port: u16, dst_port: u16, data: Vec<u8>) -> Result<(), &'static str> {
    // Construct UDP header
    let mut udp_packet = Vec::with_capacity(8 + data.len());
    udp_packet.extend_from_slice(&src_port.to_be_bytes());
    udp_packet.extend_from_slice(&dst_port.to_be_bytes());
    udp_packet.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    udp_packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (would calculate properly)
    udp_packet.extend_from_slice(&data);

    // Send to network layer (would use real IP addresses)
    crate::network::send_ip_packet(
        [127, 0, 0, 1], // Source IP
        [127, 0, 0, 1], // Destination IP
        crate::network::ip::IP_PROTOCOL_UDP,
        udp_packet,
    )
}

/// Clean up expired UDP sockets
pub fn cleanup_expired_sockets() {
    let mut sockets = UDP_SOCKETS.lock();
    let mut to_remove = Vec::new();

    // Check each socket for inactivity
    for (port, socket) in sockets.iter() {
        let rx_buf = socket.rx_buffer.lock();
        let tx_buf = socket.tx_buffer.lock();

        // Remove sockets with stale data (both buffers empty for cleanup)
        let should_cleanup = rx_buf.is_empty() && tx_buf.is_empty();

        if should_cleanup && is_ephemeral_port(*port) {
            to_remove.push(*port);
        }
    }

    // Remove expired sockets
    for port in to_remove {
        sockets.remove(&port);
        crate::log::logger::log_debug!("Cleaned up expired UDP socket on port {}", port);
    }
}

/// Check if port is in ephemeral range (can be cleaned up)
fn is_ephemeral_port(port: u16) -> bool {
    port >= 49152 // Ephemeral port range starts at 49152
}
