// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! UDP public API functions.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::socket::UdpSocket;
use super::types::{GlobalUdpStats, UdpPacket, UdpSocketId, UdpState};

/// Global socket table
pub static SOCKET_TABLE: Mutex<BTreeMap<UdpSocketId, UdpSocket>> = Mutex::new(BTreeMap::new());
static NEXT_SOCKET_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_EPHEMERAL_PORT: AtomicU32 = AtomicU32::new(49152);

/// Global UDP statistics
pub static GLOBAL_STATS: GlobalUdpStats = GlobalUdpStats {
    packets_sent: AtomicU64::new(0),
    packets_received: AtomicU64::new(0),
    bytes_sent: AtomicU64::new(0),
    bytes_received: AtomicU64::new(0),
};

/// Allocate an ephemeral port
pub fn allocate_ephemeral_port() -> Result<u16, &'static str> {
    let sockets = SOCKET_TABLE.lock();
    for _ in 0..1000 {
        let port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::SeqCst);
        let port = if port > 65535 {
            NEXT_EPHEMERAL_PORT.store(49152, Ordering::SeqCst);
            49152
        } else {
            port as u16
        };

        let in_use =
            sockets.iter().any(|(_, s)| s.local_port == port && s.state != UdpState::Closed);
        if !in_use {
            return Ok(port);
        }
    }
    Err("No ephemeral ports available")
}

/// Create a new UDP socket and register it
pub fn create_socket() -> Result<UdpSocketId, &'static str> {
    let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
    let socket = UdpSocket::new(id);
    SOCKET_TABLE.lock().insert(id, socket);
    Ok(id)
}

/// Get a socket by ID
pub fn get_socket(id: UdpSocketId) -> Option<UdpSocket> {
    SOCKET_TABLE.lock().remove(&id)
}

/// Return a socket to the table
pub fn return_socket(socket: UdpSocket) {
    SOCKET_TABLE.lock().insert(socket.id(), socket);
}

/// Close and remove a socket
pub fn close_socket(id: UdpSocketId) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(mut socket) = sockets.remove(&id) {
        socket.close();
        Ok(())
    } else {
        Err("Socket not found")
    }
}

/// Bind a socket to a port
pub fn bind(id: UdpSocketId, port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.bind(port)
    } else {
        Err("Socket not found")
    }
}

/// Connect a socket to a remote address
pub fn connect(id: UdpSocketId, addr: [u8; 4], port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.connect(addr, port)
    } else {
        Err("Socket not found")
    }
}

/// Send data on a socket
pub fn send(id: UdpSocketId, data: &[u8]) -> Result<usize, &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.send(data)
    } else {
        Err("Socket not found")
    }
}

/// Send data to a specific address
pub fn send_to(
    id: UdpSocketId,
    data: &[u8],
    addr: [u8; 4],
    port: u16,
) -> Result<usize, &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.send_to(data, addr, port)
    } else {
        Err("Socket not found")
    }
}

/// Receive data from a socket
pub fn recv(id: UdpSocketId, buf: &mut [u8]) -> Result<usize, &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.recv(buf)
    } else {
        Err("Socket not found")
    }
}

/// Receive data with source address
pub fn recv_from(id: UdpSocketId, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.recv_from(buf)
    } else {
        Err("Socket not found")
    }
}

/// Process incoming UDP packet
pub fn process_incoming_packet(
    src_addr: [u8; 4],
    dst_port: u16,
    src_port: u16,
    data: &[u8],
) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();

    for (_, socket) in sockets.iter_mut() {
        if socket.local_port == dst_port && socket.state != UdpState::Closed {
            if socket.state == UdpState::Connected {
                if let (Some(addr), Some(port)) = (socket.remote_addr, socket.remote_port) {
                    if addr != src_addr || port != src_port {
                        continue;
                    }
                }
            }

            let packet = UdpPacket {
                src_addr,
                src_port,
                data: data.to_vec(),
                timestamp: crate::time::timestamp_millis(),
            };

            GLOBAL_STATS.packets_received.fetch_add(1, Ordering::Relaxed);
            GLOBAL_STATS.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);

            return socket.queue_packet(packet);
        }
    }

    Err("No socket listening on port")
}

/// Get global UDP statistics
pub fn get_global_stats() -> (u64, u64, u64, u64) {
    (
        GLOBAL_STATS.packets_sent.load(Ordering::Relaxed),
        GLOBAL_STATS.packets_received.load(Ordering::Relaxed),
        GLOBAL_STATS.bytes_sent.load(Ordering::Relaxed),
        GLOBAL_STATS.bytes_received.load(Ordering::Relaxed),
    )
}

/// Initialize UDP subsystem
pub fn init() -> Result<(), &'static str> {
    GLOBAL_STATS.packets_sent.store(0, Ordering::SeqCst);
    GLOBAL_STATS.packets_received.store(0, Ordering::SeqCst);
    GLOBAL_STATS.bytes_sent.store(0, Ordering::SeqCst);
    GLOBAL_STATS.bytes_received.store(0, Ordering::SeqCst);
    crate::log::info!("UDP subsystem initialized");
    Ok(())
}

pub fn send_udp6(
    src: &crate::network::ipv6::Ipv6Address,
    src_port: u16,
    dst: &crate::network::ipv6::Ipv6Address,
    dst_port: u16,
    data: &[u8],
) -> Result<(), i32> {
    use alloc::vec::Vec;
    let mut udp = Vec::with_capacity(8 + data.len());
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    udp.push(0);
    udp.push(0);
    udp.extend_from_slice(data);
    let sum = crate::network::ipv6::packet::compute_pseudo_header_checksum(
        &src,
        &dst,
        17,
        udp.len() as u32,
    );
    let cs = crate::network::ipv6::packet::finish_checksum(sum, &udp);
    udp[6] = (cs >> 8) as u8;
    udp[7] = cs as u8;
    let pkt = crate::network::ipv6::packet::build_ipv6_packet(
        *src,
        *dst,
        crate::network::ipv6::header::NextHeader::Udp,
        64,
        &udp,
    );
    crate::network::stack::send_ipv6_packet(&pkt)
}
