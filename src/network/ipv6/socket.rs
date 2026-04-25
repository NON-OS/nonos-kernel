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
use super::address::Ipv6Address;
use super::header::NextHeader;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6SocketType {
    Raw,
    Tcp,
    Udp,
    Icmpv6,
}

#[derive(Debug, Clone)]
pub struct Ipv6SocketOptions {
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub v6only: bool,
    pub multicast_loop: bool,
    pub multicast_hops: u8,
    pub unicast_hops: u8,
}

impl Default for Ipv6SocketOptions {
    fn default() -> Self {
        Self {
            hop_limit: 64,
            traffic_class: 0,
            v6only: false,
            multicast_loop: true,
            multicast_hops: 1,
            unicast_hops: 64,
        }
    }
}

pub struct Ipv6Socket {
    pub socket_type: Ipv6SocketType,
    pub protocol: NextHeader,
    pub local_addr: Mutex<Option<Ipv6Address>>,
    pub local_port: Mutex<u16>,
    pub remote_addr: Mutex<Option<Ipv6Address>>,
    pub remote_port: Mutex<u16>,
    pub options: Mutex<Ipv6SocketOptions>,
    pub recv_buf: Mutex<VecDeque<(Vec<u8>, Ipv6Address, u16)>>,
    pub connected: core::sync::atomic::AtomicBool,
}

impl Ipv6Socket {
    pub fn new(socket_type: Ipv6SocketType, protocol: NextHeader) -> Self {
        Self {
            socket_type,
            protocol,
            local_addr: Mutex::new(None),
            local_port: Mutex::new(0),
            remote_addr: Mutex::new(None),
            remote_port: Mutex::new(0),
            options: Mutex::new(Ipv6SocketOptions::default()),
            recv_buf: Mutex::new(VecDeque::with_capacity(64)),
            connected: core::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn bind(&self, addr: Ipv6Address, port: u16) -> Result<(), i32> {
        *self.local_addr.lock() = Some(addr);
        *self.local_port.lock() = port;
        Ok(())
    }

    pub fn connect(&self, addr: Ipv6Address, port: u16) -> Result<(), i32> {
        *self.remote_addr.lock() = Some(addr);
        *self.remote_port.lock() = port;
        self.connected.store(true, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn send(&self, data: &[u8]) -> Result<usize, i32> {
        let remote = self.remote_addr.lock().ok_or(-107)?;
        let local = self.local_addr.lock().unwrap_or(Ipv6Address::UNSPECIFIED);
        let opts = self.options.lock();
        let pkt =
            super::packet::build_ipv6_packet(local, remote, self.protocol, opts.hop_limit, data);
        crate::network::stack::send_ipv6_packet(&pkt)?;
        Ok(data.len())
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, Ipv6Address, u16), i32> {
        let mut q = self.recv_buf.lock();
        let (data, addr, port) = q.pop_front().ok_or(-11)?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok((len, addr, port))
    }

    pub fn deliver(&self, data: &[u8], src: Ipv6Address, src_port: u16) {
        self.recv_buf.lock().push_back((data.to_vec(), src, src_port));
    }
}

pub fn create_ipv6_socket(sock_type: Ipv6SocketType, protocol: NextHeader) -> Arc<Ipv6Socket> {
    Arc::new(Ipv6Socket::new(sock_type, protocol))
}

pub fn bind_ipv6(sock: &Arc<Ipv6Socket>, addr: Ipv6Address, port: u16) -> Result<(), i32> {
    sock.bind(addr, port)
}
