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


use core::sync::atomic::{AtomicU32, Ordering};

pub type SmolHandle = smoltcp::iface::SocketHandle;
pub type Ipv4Address = [u8; 4];
pub type Ipv6Address = [u8; 16];

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone)]
pub struct TcpSocket {
    id: u32,
    pub remote_port: u16,
}

impl TcpSocket {
    pub fn new() -> Self {
        Self { id: NEXT_ID.fetch_add(1, Ordering::SeqCst), remote_port: 0 }
    }
    pub fn connection_id(&self) -> u32 { self.id }
    pub fn from_connection(id: u32) -> Self { Self { id, remote_port: 0 } }
}

impl Default for TcpSocket {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone)]
pub struct Socket {
    conn_id: Option<u32>,
}

impl Socket {
    pub fn new() -> Self { Self { conn_id: None } }
    pub fn for_connection(id: u32) -> Self { Self { conn_id: Some(id) } }
    pub fn connection_id(&self) -> Option<u32> { self.conn_id }
}

impl Default for Socket {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Default, Clone)]
pub struct NetworkStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
}

#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub id: u32,
    pub is_tcp: bool,
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub state: u8,
    pub rx_available: usize,
    pub tx_available: usize,
    pub can_recv: bool,
    pub can_send: bool,
    pub has_error: bool,
    pub is_closed: bool,
    pub peer_closed: bool,
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub lease_time: u32,
}

pub(super) struct ConnectionEntry {
    pub id: u32,
    pub tcp: SmolHandle,
    pub last_activity_ms: u64,
    pub closed: bool,
}
