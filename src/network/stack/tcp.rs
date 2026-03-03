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


use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::sync::atomic::Ordering;

use smoltcp::{
    socket::tcp,
    time::Duration as SmolDuration,
    wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address},
};

use super::core::NetworkStack;
use super::device::now_ms;
use super::types::{ConnectionEntry, TcpSocket, Socket};
use crate::network::ip::IpAddress;

impl NetworkStack {
    pub fn bind_tcp_port(&self, port: u16) -> Result<(), &'static str> {
        let mut sockets = self.sockets.lock();
        let rx = tcp::SocketBuffer::new(vec![0; 8192]);
        let tx = tcp::SocketBuffer::new(vec![0; 8192]);
        let mut s = tcp::Socket::new(rx, tx);
        s.listen(port).map_err(|_| "listen failed")?;
        let _ = sockets.add(s);
        Ok(())
    }

    pub fn listen_tcp(&self, backlog: usize) -> Result<(), &'static str> {
        if backlog == 0 {
            return Err("backlog must be > 0");
        }
        crate::log::debug!("tcp: listen backlog set to {}", backlog);
        Ok(())
    }

    pub fn accept_tcp_connection(&self) -> Result<u32, &'static str> {
        let sockets = self.sockets.lock();
        let now = now_ms();
        let handles: Vec<_> = sockets.iter().map(|h| h.0).collect();
        for h in handles {
            let sock = sockets.get::<tcp::Socket>(h);
            if sock.is_active() && (sock.may_recv() || sock.may_send()) {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                drop(sockets);
                let mut conns = self.conns.lock();
                conns.insert(id, ConnectionEntry { id, tcp: h, last_activity_ms: now, closed: false });
                return Ok(id);
            }
        }
        Err("no pending connection")
    }
}

impl NetworkStack {
    pub fn connect_tcp(&self, addr: IpAddress, port: u16) -> Result<(), &'static str> {
        match addr {
            IpAddress::V4(a) => {
                let tmp = TcpSocket::new();
                self.tcp_connect(&tmp, a, port)
            }
            IpAddress::V6(a) => {
                let tmp = TcpSocket::new();
                self.tcp_connect_v6(&tmp, a, port)
            }
        }
    }

    pub fn tcp_connect(&self, sock: &TcpSocket, addr_v4: [u8; 4], port: u16) -> Result<(), &'static str> {
        let mut sockets = self.sockets.lock();
        let tcp_rx = tcp::SocketBuffer::new(vec![0; 16384]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0; 16384]);
        let mut s = tcp::Socket::new(tcp_rx, tcp_tx);
        s.set_timeout(Some(SmolDuration::from_millis(10_000)));
        let handle = sockets.add(s);
        let id = sock.connection_id();

        {
            let mut conns = self.conns.lock();
            conns.insert(id, ConnectionEntry { id, tcp: handle, last_activity_ms: now_ms(), closed: false });
        }
        drop(sockets);

        {
            let mut sockets = self.sockets.lock();
            let mut iface = self.iface.lock();
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            let endpoint = smoltcp::wire::IpEndpoint::new(
                SmolIpAddress::Ipv4(SmolIpv4Address::new(addr_v4[0], addr_v4[1], addr_v4[2], addr_v4[3])), port
            );
            let local_endpoint = (SmolIpAddress::Ipv4(SmolIpv4Address::new(0, 0, 0, 0)), 0);
            let mut ctx = iface.context();
            socket.connect(&mut ctx, endpoint, local_endpoint).map_err(|_| "tcp connect error")?;
        }

        self.wait_for_connection(handle)
    }

    pub fn tcp_connect_v6(&self, sock: &TcpSocket, addr_v6: [u8; 16], port: u16) -> Result<(), &'static str> {
        let mut sockets = self.sockets.lock();
        let tcp_rx = tcp::SocketBuffer::new(vec![0; 16384]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0; 16384]);
        let mut s = tcp::Socket::new(tcp_rx, tcp_tx);
        s.set_timeout(Some(SmolDuration::from_millis(10_000)));
        let handle = sockets.add(s);
        let id = sock.connection_id();

        {
            let mut conns = self.conns.lock();
            conns.insert(id, ConnectionEntry { id, tcp: handle, last_activity_ms: now_ms(), closed: false });
        }
        drop(sockets);

        {
            let mut sockets = self.sockets.lock();
            let mut iface = self.iface.lock();
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            let endpoint = smoltcp::wire::IpEndpoint::new(
                SmolIpAddress::Ipv6(SmolIpv6Address::from_bytes(&addr_v6)), port
            );
            let local_endpoint = (SmolIpAddress::Ipv6(SmolIpv6Address::UNSPECIFIED), 0);
            let mut ctx = iface.context();
            socket.connect(&mut ctx, endpoint, local_endpoint).map_err(|_| "tcp connect error")?;
        }

        self.wait_for_connection(handle)
    }

    pub fn tcp_connect_ip(&self, sock: &TcpSocket, addr: IpAddress, port: u16) -> Result<(), &'static str> {
        match addr {
            IpAddress::V4(v4) => self.tcp_connect(sock, v4, port),
            IpAddress::V6(v6) => self.tcp_connect_v6(sock, v6, port),
        }
    }

    fn wait_for_connection(&self, handle: smoltcp::iface::SocketHandle) -> Result<(), &'static str> {
        let start = now_ms();
        let mut iterations = 0u32;
        const MAX_ITER: u32 = 1_500;

        loop {
            self.poll();

            {
                let sockets = self.sockets.lock();
                let s: &tcp::Socket = sockets.get(handle);
                if s.is_active() && s.may_send() { break; }
            }

            if now_ms().saturating_sub(start) > 1_000 { return Err("tcp connect timeout"); }

            iterations += 1;
            if iterations >= MAX_ITER { return Err("tcp connect timeout"); }

            crate::time::yield_now();
        }
        Ok(())
    }

    pub fn get_local_port(&self, sock: &TcpSocket) -> Option<u16> {
        let conns = self.conns.lock();
        let c = conns.get(&sock.connection_id())?;
        let sockets = self.sockets.lock();
        let s = sockets.get::<tcp::Socket>(c.tcp);
        s.local_endpoint().map(|ep| ep.port)
    }
}

impl NetworkStack {
    pub fn tcp_send(&self, conn_id: u32, buf: &[u8]) -> Result<usize, &'static str> {
        let handle = {
            let mut conns = self.conns.lock();
            let c = conns.get_mut(&conn_id).ok_or("no such connection")?;
            if c.closed { return Err("closed"); }
            c.last_activity_ms = now_ms();
            c.tcp
        };

        let mut sent = 0usize;
        let start = now_ms();
        let mut iterations = 0u32;
        const MAX_ITER: u32 = 2_000;

        loop {
            {
                let mut sockets = self.sockets.lock();
                let s: &mut tcp::Socket = sockets.get_mut(handle);
                if !s.may_send() { return Err("send not permitted"); }
                match s.send_slice(&buf[sent..]) {
                    Ok(n) if n > 0 => {
                        sent += n;
                        let mut stats = self.stats.lock();
                        stats.tx_packets += 1;
                        stats.tx_bytes += n as u64;
                        if sent == buf.len() { break; }
                    }
                    Ok(_) | Err(_) => {}
                }
            }
            self.poll();

            if now_ms().saturating_sub(start) > 5_000 { return Err("send timeout"); }

            iterations += 1;
            if iterations >= MAX_ITER { return Err("send timeout"); }

            crate::time::yield_now();
        }
        Ok(sent)
    }

    pub fn tcp_receive(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        let handle = {
            let conns = self.conns.lock();
            let c = conns.get(&conn_id).ok_or("no such connection")?;
            c.tcp
        };

        let mut out = Vec::new();
        let start = now_ms();
        let mut iterations = 0u32;
        const MAX_ITER: u32 = 1_500;

        loop {
            {
                let mut sockets = self.sockets.lock();
                let s: &mut tcp::Socket = sockets.get_mut(handle);
                let available = s.recv_queue();
                if available > 0 {
                    let to_take = min(available, max_len);
                    out.resize(to_take, 0);
                    match s.recv_slice(&mut out) {
                        Ok(n) if n > 0 => {
                            let mut stats = self.stats.lock();
                            stats.rx_packets += 1;
                            stats.rx_bytes += n as u64;
                            out.truncate(n);
                            return Ok(out);
                        }
                        _ => {}
                    }
                } else if !s.can_recv() && !s.may_send() {
                    return Ok(Vec::new());
                }
            }
            self.poll();

            if now_ms().saturating_sub(start) > 2_000 { return Ok(Vec::new()); }

            iterations += 1;
            if iterations >= MAX_ITER { return Ok(Vec::new()); }

            crate::time::yield_now();
        }
    }

    pub fn tcp_is_closed(&self, conn_id: u32) -> Option<bool> {
        let conns = self.conns.lock();
        let c = conns.get(&conn_id)?;
        let sockets = self.sockets.lock();
        let s: &tcp::Socket = sockets.get(c.tcp);
        Some(!s.is_active())
    }

    pub fn tcp_close(&self, conn_id: u32) -> Result<(), &'static str> {
        let handle = {
            let mut conns = self.conns.lock();
            let c = conns.get_mut(&conn_id).ok_or("no such connection")?;
            c.closed = true;
            c.tcp
        };
        {
            let mut sockets = self.sockets.lock();
            let s: &mut tcp::Socket = sockets.get_mut(handle);
            let _ = s.close();
        }
        Ok(())
    }

    pub fn send_tcp_data(&self, socket: &Socket, data: &[u8]) -> Result<usize, &'static str> {
        let id = socket.connection_id()
            .or_else(|| self.pick_single_active_conn())
            .ok_or("no unambiguous connection")?;
        self.tcp_send(id, data)
    }

    pub fn recv_tcp_data(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        self.tcp_receive(conn_id, max_len)
    }

    pub fn send_tcp_packet(&self, data: &[u8]) -> Result<(), &'static str> {
        let id = self.pick_single_active_conn().ok_or("no active tcp connection")?;
        let _ = self.tcp_send(id, data)?;
        Ok(())
    }
}
