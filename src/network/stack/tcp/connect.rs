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
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::time::Duration as SmolDuration;
use smoltcp::wire::{
    IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address,
};

use super::config::get_config;
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::now_ms;
use crate::network::stack::types::ConnectionEntry;

static TCP_CONNECT_WAIT_LOGS: AtomicU64 = AtomicU64::new(0);
static TCP_CONNECT_TIMEOUT_LOGS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn tcp_state_code(state: tcp::State) -> u64 {
    match state {
        tcp::State::Closed => 0,
        tcp::State::Listen => 1,
        tcp::State::SynSent => 2,
        tcp::State::SynReceived => 3,
        tcp::State::Established => 4,
        tcp::State::FinWait1 => 5,
        tcp::State::FinWait2 => 6,
        tcp::State::CloseWait => 7,
        tcp::State::Closing => 8,
        tcp::State::LastAck => 9,
        tcp::State::TimeWait => 10,
    }
}

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

fn allocate_socket(
    stack: &NetworkStack,
    cfg: &super::config::TcpConfig,
) -> Result<SocketHandle, &'static str> {
    let mut sockets = stack.sockets.lock();
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.rx_buffer_size]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.tx_buffer_size]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);

    socket.set_timeout(Some(SmolDuration::from_millis(cfg.timeouts.connect_ms)));
    socket.set_keep_alive(Some(SmolDuration::from_millis(cfg.timeouts.keepalive_ms)));
    socket.set_nagle_enabled(cfg.nagle_enabled);

    Ok(sockets.add(socket))
}

fn initiate_connection_v4(
    stack: &NetworkStack,
    handle: SocketHandle,
    addr: [u8; 4],
    port: u16,
) -> Result<(), &'static str> {
    let mut sockets = stack.sockets.lock();
    let mut iface = stack.iface.lock();
    let socket: &mut tcp::Socket = sockets.get_mut(handle);

    let remote = smoltcp::wire::IpEndpoint::new(
        SmolIpAddress::Ipv4(SmolIpv4Address::new(addr[0], addr[1], addr[2], addr[3])),
        port,
    );
    let local_unspec = (SmolIpAddress::Ipv4(SmolIpv4Address::UNSPECIFIED), 0);
    let mut ctx = iface.context();

    match socket.connect(&mut ctx, remote, local_unspec) {
        Ok(()) => Ok(()),
        Err(tcp::ConnectError::Unaddressable) => {
            if let Some((local_ip, _prefix)) = stack.get_ipv4_config() {
                let local = (
                    SmolIpAddress::Ipv4(SmolIpv4Address::new(
                        local_ip[0],
                        local_ip[1],
                        local_ip[2],
                        local_ip[3],
                    )),
                    0,
                );
                let mut retry_ctx = iface.context();
                match socket.connect(&mut retry_ctx, remote, local) {
                    Ok(()) => {
                        crate::sys::serial::println(
                            b"[TCP] connect_v4 retry with explicit local ip succeeded",
                        );
                        Ok(())
                    }
                    Err(tcp::ConnectError::InvalidState) => {
                        crate::sys::serial::println(
                            b"[TCP] connect_v4 initiate failed reason=invalid_state",
                        );
                        Err("tcp connect invalid state")
                    }
                    Err(tcp::ConnectError::Unaddressable) => {
                        crate::sys::serial::println(
                            b"[TCP] connect_v4 initiate failed reason=unaddressable",
                        );
                        Err("tcp connect unaddressable")
                    }
                }
            } else {
                crate::sys::serial::println(
                    b"[TCP] connect_v4 initiate failed reason=unaddressable_no_local_ip",
                );
                Err("tcp connect unaddressable")
            }
        }
        Err(tcp::ConnectError::InvalidState) => {
            crate::sys::serial::println(b"[TCP] connect_v4 initiate failed reason=invalid_state");
            Err("tcp connect invalid state")
        }
    }
}

fn initiate_connection_v6(
    stack: &NetworkStack,
    handle: SocketHandle,
    addr: [u8; 16],
    port: u16,
) -> Result<(), &'static str> {
    let mut sockets = stack.sockets.lock();
    let mut iface = stack.iface.lock();
    let socket: &mut tcp::Socket = sockets.get_mut(handle);

    let remote = smoltcp::wire::IpEndpoint::new(
        SmolIpAddress::Ipv6(SmolIpv6Address::from_bytes(&addr)),
        port,
    );
    let local = (SmolIpAddress::Ipv6(SmolIpv6Address::UNSPECIFIED), 0);
    let mut ctx = iface.context();

    socket.connect(&mut ctx, remote, local).map_err(|e| {
        crate::sys::serial::print(b"[TCP] connect_v6 initiate failed port=");
        crate::sys::serial::print_dec(port as u64);
        crate::sys::serial::print(b" reason=");
        match e {
            tcp::ConnectError::InvalidState => {
                crate::sys::serial::println(b"invalid_state");
                "tcp connect invalid state"
            }
            tcp::ConnectError::Unaddressable => {
                crate::sys::serial::println(b"unaddressable");
                "tcp connect unaddressable"
            }
        }
    })
}

fn register_connection(stack: &NetworkStack, conn_id: u32, handle: SocketHandle) {
    let mut conns = stack.conns.lock();
    conns.insert(
        conn_id,
        ConnectionEntry { id: conn_id, tcp: handle, last_activity_ms: now_ms(), closed: false },
    );
}

fn wait_for_established(
    stack: &NetworkStack,
    handle: SocketHandle,
    timeout_ms: u64,
) -> Result<(), &'static str> {
    let start = now_ms();
    let poll_interval_us = 1_000u64;
    let mut backoff_multiplier = 1u64;
    let mut wait_logged = false;
    let mut last_state_code = u64::MAX;

    loop {
        stack.poll();

        {
            let sockets = stack.sockets.lock();
            let socket: &tcp::Socket = sockets.get(handle);
            let state = socket.state();
            let state_code = tcp_state_code(state);

            if state_code != last_state_code {
                crate::sys::serial::print(b"[TCP] connect state=");
                crate::sys::serial::print_dec(state_code);
                crate::sys::serial::println(b"");
                last_state_code = state_code;
            }

            if socket.is_active() && socket.may_send() {
                return Ok(());
            }

            if state == tcp::State::Closed {
                return Err("connection refused");
            }
        }

        let elapsed = now_ms().saturating_sub(start);
        if !wait_logged && elapsed >= 250 {
            let idx = TCP_CONNECT_WAIT_LOGS.fetch_add(1, AtomicOrdering::Relaxed);
            if idx < 128 {
                crate::sys::serial::print(b"[TCP] connect waiting elapsed_ms=");
                crate::sys::serial::print_dec(elapsed);
                crate::sys::serial::print(b" state=");
                crate::sys::serial::print_dec(last_state_code);
                crate::sys::serial::println(b"");
            }
            wait_logged = true;
        }

        if elapsed >= timeout_ms {
            let idx = TCP_CONNECT_TIMEOUT_LOGS.fetch_add(1, AtomicOrdering::Relaxed);
            if idx < 64 {
                crate::sys::serial::print(b"[TCP] connect timeout elapsed_ms=");
                crate::sys::serial::print_dec(elapsed);
                crate::sys::serial::print(b" state=");
                crate::sys::serial::print_dec(last_state_code);
                crate::sys::serial::println(b"");
            }
            return Err("tcp connect timeout");
        }

        crate::time::yield_now();
        let sleep_us = poll_interval_us.saturating_mul(backoff_multiplier).min(5_000);
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
