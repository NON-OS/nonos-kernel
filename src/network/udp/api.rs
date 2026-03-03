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


extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::socket::UdpSocket;
use super::types::{GlobalUdpStats, UdpPacket, UdpSocketId, UdpState};

pub static SOCKET_TABLE: Mutex<BTreeMap<UdpSocketId, UdpSocket>> = Mutex::new(BTreeMap::new());
static NEXT_SOCKET_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_EPHEMERAL_PORT: AtomicU32 = AtomicU32::new(49152);

pub static GLOBAL_STATS: GlobalUdpStats = GlobalUdpStats {
    packets_sent: AtomicU64::new(0),
    packets_received: AtomicU64::new(0),
    bytes_sent: AtomicU64::new(0),
    bytes_received: AtomicU64::new(0),
};

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

        let in_use = sockets
            .iter()
            .any(|(_, s)| s.local_port == port && s.state != UdpState::Closed);
        if !in_use {
            return Ok(port);
        }
    }
    Err("No ephemeral ports available")
}

pub fn create_socket() -> Result<UdpSocketId, &'static str> {
    let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
    let socket = UdpSocket::new(id);
    SOCKET_TABLE.lock().insert(id, socket);
    Ok(id)
}

pub fn get_socket(id: UdpSocketId) -> Option<UdpSocket> {
    SOCKET_TABLE.lock().remove(&id)
}

pub fn return_socket(socket: UdpSocket) {
    SOCKET_TABLE.lock().insert(socket.id(), socket);
}

pub fn close_socket(id: UdpSocketId) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(mut socket) = sockets.remove(&id) {
        socket.close();
        Ok(())
    } else {
        Err("Socket not found")
    }
}

pub fn bind(id: UdpSocketId, port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.bind(port)
    } else {
        Err("Socket not found")
    }
}

pub fn connect(id: UdpSocketId, addr: [u8; 4], port: u16) -> Result<(), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.connect(addr, port)
    } else {
        Err("Socket not found")
    }
}

pub fn send(id: UdpSocketId, data: &[u8]) -> Result<usize, &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.send(data)
    } else {
        Err("Socket not found")
    }
}

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

pub fn recv(id: UdpSocketId, buf: &mut [u8]) -> Result<usize, &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.recv(buf)
    } else {
        Err("Socket not found")
    }
}

pub fn recv_from(id: UdpSocketId, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), &'static str> {
    let mut sockets = SOCKET_TABLE.lock();
    if let Some(socket) = sockets.get_mut(&id) {
        socket.recv_from(buf)
    } else {
        Err("Socket not found")
    }
}

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

            GLOBAL_STATS
                .packets_received
                .fetch_add(1, Ordering::Relaxed);
            GLOBAL_STATS
                .bytes_received
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            return socket.queue_packet(packet);
        }
    }

    Err("No socket listening on port")
}

pub fn get_global_stats() -> (u64, u64, u64, u64) {
    (
        GLOBAL_STATS.packets_sent.load(Ordering::Relaxed),
        GLOBAL_STATS.packets_received.load(Ordering::Relaxed),
        GLOBAL_STATS.bytes_sent.load(Ordering::Relaxed),
        GLOBAL_STATS.bytes_received.load(Ordering::Relaxed),
    )
}

pub fn init() -> Result<(), &'static str> {
    crate::log::info!("UDP subsystem initialized");
    Ok(())
}
