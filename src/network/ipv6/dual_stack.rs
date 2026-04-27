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
use super::socket::{Ipv6Socket, Ipv6SocketType};
use alloc::sync::Arc;

pub fn is_ipv4_mapped(addr: &Ipv6Address) -> bool {
    addr.0[0..10] == [0; 10] && addr.0[10] == 0xff && addr.0[11] == 0xff
}

pub fn map_ipv4_to_ipv6(ipv4: [u8; 4]) -> Ipv6Address {
    let mut bytes = [0u8; 16];
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    bytes[12..16].copy_from_slice(&ipv4);
    Ipv6Address(bytes)
}

pub fn extract_ipv4(addr: &Ipv6Address) -> Option<[u8; 4]> {
    if is_ipv4_mapped(addr) {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&addr.0[12..16]);
        Some(v4)
    } else {
        None
    }
}

pub struct DualStackSocket {
    pub v6_socket: Arc<Ipv6Socket>,
    pub v6only: bool,
}

impl DualStackSocket {
    pub fn new(sock_type: Ipv6SocketType, protocol: NextHeader) -> Self {
        Self { v6_socket: Arc::new(Ipv6Socket::new(sock_type, protocol)), v6only: false }
    }

    pub fn set_v6only(&mut self, v6only: bool) {
        self.v6only = v6only;
    }

    pub fn bind(&self, addr: Ipv6Address, port: u16) -> Result<(), i32> {
        self.v6_socket.bind(addr, port)
    }

    pub fn connect(&self, addr: Ipv6Address, port: u16) -> Result<(), i32> {
        if self.v6only && is_ipv4_mapped(&addr) {
            return Err(-99);
        }
        self.v6_socket.connect(addr, port)
    }

    pub fn send(&self, data: &[u8]) -> Result<usize, i32> {
        let remote = self.v6_socket.remote_addr.lock().ok_or(-107)?;
        if self.v6only && is_ipv4_mapped(&remote) {
            return Err(-99);
        }
        if let Some(v4) = extract_ipv4(&remote) {
            return self.send_v4(data, v4, *self.v6_socket.remote_port.lock());
        }
        self.v6_socket.send(data)
    }

    fn send_v4(&self, data: &[u8], dst: [u8; 4], port: u16) -> Result<usize, i32> {
        let _ = (data, dst, port);
        crate::network::tcp::send_data(dst, port, data)?;
        Ok(data.len())
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, Ipv6Address, u16), i32> {
        self.v6_socket.recv(buf)
    }

    pub fn deliver_v4(&self, data: &[u8], src: [u8; 4], port: u16) {
        if self.v6only {
            return;
        }
        let mapped = map_ipv4_to_ipv6(src);
        self.v6_socket.deliver(data, mapped, port);
    }

    pub fn deliver_v6(&self, data: &[u8], src: Ipv6Address, port: u16) {
        self.v6_socket.deliver(data, src, port);
    }
}

pub fn create_dual_stack_socket(
    sock_type: Ipv6SocketType,
    protocol: NextHeader,
) -> DualStackSocket {
    DualStackSocket::new(sock_type, protocol)
}
