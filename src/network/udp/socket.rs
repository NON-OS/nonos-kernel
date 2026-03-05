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

//! UDP socket implementation.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::api::{allocate_ephemeral_port, GLOBAL_STATS, SOCKET_TABLE};
use super::types::{UdpHeader, UdpPacket, UdpSocketId, UdpState, UdpStats};

/// UDP socket structure
#[derive(Debug)]
pub struct UdpSocket {
    pub(super) id: UdpSocketId,
    pub(super) state: UdpState,
    pub(super) local_port: u16,
    pub(super) remote_addr: Option<[u8; 4]>,
    pub(super) remote_port: Option<u16>,
    pub(super) recv_buffer: Vec<UdpPacket>,
    pub(super) recv_buffer_size: usize,
    pub(super) stats: UdpStats,
}

impl UdpSocket {
    /// Create a new UDP socket
    pub fn new(id: UdpSocketId) -> Self {
        Self {
            id,
            state: UdpState::Unbound,
            local_port: 0,
            remote_addr: None,
            remote_port: None,
            recv_buffer: Vec::with_capacity(64),
            recv_buffer_size: 65536,
            stats: UdpStats::default(),
        }
    }

    /// Get socket ID
    pub fn id(&self) -> UdpSocketId {
        self.id
    }

    /// Get socket state
    pub fn state(&self) -> UdpState {
        self.state
    }

    /// Get local port
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Bind to a local port
    pub fn bind(&mut self, port: u16) -> Result<(), &'static str> {
        if self.state != UdpState::Unbound {
            return Err("Socket already bound");
        }

        let sockets = SOCKET_TABLE.lock();
        for (_, sock) in sockets.iter() {
            if sock.local_port == port && sock.state != UdpState::Closed {
                return Err("Port already in use");
            }
        }
        drop(sockets);

        self.local_port = port;
        self.state = UdpState::Bound;
        Ok(())
    }

    /// Connect to a remote address (sets default destination)
    pub fn connect(&mut self, addr: [u8; 4], port: u16) -> Result<(), &'static str> {
        if self.state == UdpState::Closed {
            return Err("Socket closed");
        }

        if self.state == UdpState::Unbound {
            self.local_port = allocate_ephemeral_port()?;
            self.state = UdpState::Bound;
        }

        self.remote_addr = Some(addr);
        self.remote_port = Some(port);
        self.state = UdpState::Connected;
        Ok(())
    }

    /// Send data to the connected remote address
    pub fn send(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let addr = self.remote_addr.ok_or("Not connected")?;
        let port = self.remote_port.ok_or("Not connected")?;
        self.send_to(data, addr, port)
    }

    /// Send data to a specific address
    pub fn send_to(
        &mut self,
        data: &[u8],
        _dest_ip: [u8; 4],
        port: u16,
    ) -> Result<usize, &'static str> {
        if self.state == UdpState::Closed {
            return Err("Socket closed");
        }

        if self.state == UdpState::Unbound {
            self.local_port = allocate_ephemeral_port()?;
            self.state = UdpState::Bound;
        }

        if data.len() > 65507 {
            return Err("Data too large for UDP");
        }

        let header = UdpHeader {
            src_port: self.local_port,
            dst_port: port,
            length: (8 + data.len()) as u16,
            checksum: 0,
        };

        if let Some(_stack) = crate::network::get_network_stack() {
            let mut packet = Vec::with_capacity(8 + data.len());
            packet.extend_from_slice(&header.serialize());
            packet.extend_from_slice(data);

            self.stats.packets_sent += 1;
            self.stats.bytes_sent += data.len() as u64;

            GLOBAL_STATS
                .packets_sent
                .fetch_add(1, Ordering::Relaxed);
            GLOBAL_STATS
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);

            return Ok(data.len());
        }

        Err("Network stack not initialized")
    }

    /// Receive data from the socket
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if self.state == UdpState::Closed {
            return Err("Socket closed");
        }

        if self.recv_buffer.is_empty() {
            return Err("No data available");
        }

        let packet = self.recv_buffer.remove(0);
        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);

        self.stats.packets_received += 1;
        self.stats.bytes_received += len as u64;

        Ok(len)
    }

    /// Receive data with source address
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16), &'static str> {
        if self.state == UdpState::Closed {
            return Err("Socket closed");
        }

        if self.recv_buffer.is_empty() {
            return Err("No data available");
        }

        let packet = self.recv_buffer.remove(0);
        let len = packet.data.len().min(buf.len());
        buf[..len].copy_from_slice(&packet.data[..len]);

        self.stats.packets_received += 1;
        self.stats.bytes_received += len as u64;

        Ok((len, packet.src_addr, packet.src_port))
    }

    /// Queue received packet
    pub fn queue_packet(&mut self, packet: UdpPacket) -> Result<(), &'static str> {
        let total_size: usize = self.recv_buffer.iter().map(|p| p.data.len()).sum();
        if total_size + packet.data.len() > self.recv_buffer_size {
            self.stats.errors += 1;
            return Err("Receive buffer full");
        }

        self.recv_buffer.push(packet);
        Ok(())
    }

    /// Check if data is available
    pub fn has_data(&self) -> bool {
        !self.recv_buffer.is_empty()
    }

    /// Get socket statistics
    pub fn stats(&self) -> &UdpStats {
        &self.stats
    }

    /// Close the socket
    pub fn close(&mut self) {
        self.state = UdpState::Closed;
        self.recv_buffer.clear();
    }
}
