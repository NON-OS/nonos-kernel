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
use core::sync::atomic::Ordering;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::Duration as SmolDuration;
use smoltcp::wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address};

use super::config::get_config;
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::now_ms;
use crate::network::stack::types::ConnectionEntry;

pub fn connect_v4(stack: &NetworkStack, addr_v4: [u8; 4], port: u16) -> Result<u32, &'static str> {
    let cfg = get_config();
    let handle = allocate_socket(stack, &cfg)?;
    let conn_id = stack.next_id.fetch_add(1, Ordering::SeqCst);

    if let Err(e) = initiate_connection_v4(stack, handle, addr_v4, port) {
        cleanup_failed_socket(stack, handle, conn_id);
        return Err(e);
    }

    register_connection(stack, conn_id, handle);

    if let Err(e) = wait_for_established(stack, handle, cfg.timeouts.connect_ms) {
        cleanup_failed_socket(stack, handle, conn_id);
        return Err(e);
    }

    Ok(conn_id)
}

pub fn connect_v6(stack: &NetworkStack, addr_v6: [u8; 16], port: u16) -> Result<u32, &'static str> {
    let cfg = get_config();
    let handle = allocate_socket(stack, &cfg)?;
    let conn_id = stack.next_id.fetch_add(1, Ordering::SeqCst);

    if let Err(e) = initiate_connection_v6(stack, handle, addr_v6, port) {
        cleanup_failed_socket(stack, handle, conn_id);
        return Err(e);
    }

    register_connection(stack, conn_id, handle);

    if let Err(e) = wait_for_established(stack, handle, cfg.timeouts.connect_ms) {
        cleanup_failed_socket(stack, handle, conn_id);
        return Err(e);
    }

    Ok(conn_id)
}

fn allocate_socket(stack: &NetworkStack, cfg: &super::config::TcpConfig) -> Result<SocketHandle, &'static str> {
    let mut sockets = stack.sockets.lock();
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.rx_buffer_size]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.tx_buffer_size]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);

    socket.set_timeout(Some(SmolDuration::from_millis(cfg.timeouts.connect_ms)));
    socket.set_keep_alive(Some(SmolDuration::from_millis(cfg.timeouts.keepalive_ms)));
    socket.set_nagle_enabled(cfg.nagle_enabled);

    Ok(sockets.add(socket))
}

fn initiate_connection_v4(stack: &NetworkStack, handle: SocketHandle, addr: [u8; 4], port: u16) -> Result<(), &'static str> {
    let mut sockets = stack.sockets.lock();
    let mut iface = stack.iface.lock();
    let socket: &mut tcp::Socket = sockets.get_mut(handle);

    let remote = smoltcp::wire::IpEndpoint::new(
        SmolIpAddress::Ipv4(SmolIpv4Address::new(addr[0], addr[1], addr[2], addr[3])),
        port,
    );
    let local = (SmolIpAddress::Ipv4(SmolIpv4Address::UNSPECIFIED), 0);
    let mut ctx = iface.context();

    socket.connect(&mut ctx, remote, local).map_err(|_| "tcp connect initiation failed")
}

fn initiate_connection_v6(stack: &NetworkStack, handle: SocketHandle, addr: [u8; 16], port: u16) -> Result<(), &'static str> {
    let mut sockets = stack.sockets.lock();
    let mut iface = stack.iface.lock();
    let socket: &mut tcp::Socket = sockets.get_mut(handle);

    let remote = smoltcp::wire::IpEndpoint::new(
        SmolIpAddress::Ipv6(SmolIpv6Address::from_bytes(&addr)),
        port,
    );
    let local = (SmolIpAddress::Ipv6(SmolIpv6Address::UNSPECIFIED), 0);
    let mut ctx = iface.context();

    socket.connect(&mut ctx, remote, local).map_err(|_| "tcp connect initiation failed")
}

fn register_connection(stack: &NetworkStack, conn_id: u32, handle: SocketHandle) {
    let mut conns = stack.conns.lock();
    conns.insert(conn_id, ConnectionEntry {
        id: conn_id,
        tcp: handle,
        last_activity_ms: now_ms(),
        closed: false,
    });
}

fn wait_for_established(stack: &NetworkStack, handle: SocketHandle, timeout_ms: u64) -> Result<(), &'static str> {
    let start = now_ms();
    let poll_interval_us = 1_000u64;
    let mut backoff_multiplier = 1u64;

    loop {
        stack.poll();

        {
            let sockets = stack.sockets.lock();
            let socket: &tcp::Socket = sockets.get(handle);

            if socket.is_active() && socket.may_send() {
                return Ok(());
            }

            if socket.state() == tcp::State::Closed {
                return Err("connection refused");
            }
        }

        let elapsed = now_ms().saturating_sub(start);
        if elapsed >= timeout_ms {
            return Err("tcp connect timeout");
        }

        let sleep_us = poll_interval_us.saturating_mul(backoff_multiplier).min(50_000);
        crate::time::sleep_us(sleep_us);

        if backoff_multiplier < 50 {
            backoff_multiplier = backoff_multiplier.saturating_add(1);
        }
    }
}

fn cleanup_failed_socket(stack: &NetworkStack, handle: SocketHandle, conn_id: u32) {
    {
        let mut conns = stack.conns.lock();
        conns.remove(&conn_id);
    }
    {
        let mut sockets = stack.sockets.lock();
        let socket: &mut tcp::Socket = sockets.get_mut(handle);
        socket.abort();
        sockets.remove(handle);
    }
    crate::log::debug!("tcp: cleaned up failed connection {}", conn_id);
}
