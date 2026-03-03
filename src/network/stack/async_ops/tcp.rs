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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::Mutex;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress as SmolIpAddress, Ipv4Address as SmolIpv4Address, IpEndpoint};
use super::AsyncResult;
use super::super::core::get_network_stack;
use super::super::device::now_ms;

static TCP_CONN_ACTIVE: AtomicBool = AtomicBool::new(false);
static TCP_CONN_START: AtomicU64 = AtomicU64::new(0);
static TCP_CONN_ID: AtomicU32 = AtomicU32::new(0);
pub(super) static TCP_HANDLE: Mutex<Option<smoltcp::iface::SocketHandle>> = Mutex::new(None);
static TCP_CONNECTED: AtomicBool = AtomicBool::new(false);

pub fn tcp_start_connect(addr: [u8; 4], port: u16) -> Result<u32, &'static str> {
    if TCP_CONN_ACTIVE.load(Ordering::SeqCst) {
        return Err("tcp connection already in progress");
    }

    let ns = get_network_stack().ok_or("no network stack")?;

    let mut sockets = ns.sockets.lock();
    let rx = tcp::SocketBuffer::new(vec![0; 8192]);
    let tx = tcp::SocketBuffer::new(vec![0; 8192]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_timeout(Some(smoltcp::time::Duration::from_millis(5000)));
    let handle = sockets.add(socket);

    {
        let mut iface = ns.iface.lock();
        let s: &mut tcp::Socket = sockets.get_mut(handle);
        let endpoint = IpEndpoint::new(
            SmolIpAddress::Ipv4(SmolIpv4Address::new(addr[0], addr[1], addr[2], addr[3])),
            port
        );
        let local = (SmolIpAddress::Ipv4(SmolIpv4Address::new(0, 0, 0, 0)), 0);
        let mut ctx = iface.context();
        s.connect(&mut ctx, endpoint, local).map_err(|_| "tcp connect start failed")?;
    }
    drop(sockets);

    let conn_id = TCP_CONN_ID.fetch_add(1, Ordering::SeqCst) + 1;

    *TCP_HANDLE.lock() = Some(handle);
    TCP_CONN_START.store(now_ms(), Ordering::SeqCst);
    TCP_CONNECTED.store(false, Ordering::SeqCst);
    TCP_CONN_ACTIVE.store(true, Ordering::SeqCst);

    Ok(conn_id)
}

pub fn tcp_poll_connect() -> AsyncResult<()> {
    if !TCP_CONN_ACTIVE.load(Ordering::SeqCst) {
        if TCP_CONNECTED.load(Ordering::SeqCst) {
            return AsyncResult::Ready(());
        }
        return AsyncResult::Error("no tcp connection active");
    }

    let elapsed = now_ms().saturating_sub(TCP_CONN_START.load(Ordering::SeqCst));
    if elapsed > 3000 {
        tcp_cleanup();
        return AsyncResult::Error("tcp connect timeout");
    }

    let ns = match get_network_stack() {
        Some(s) => s,
        None => {
            tcp_cleanup();
            return AsyncResult::Error("no network");
        }
    };

    ns.poll();

    let handle = match *TCP_HANDLE.lock() {
        Some(h) => h,
        None => {
            tcp_cleanup();
            return AsyncResult::Error("no tcp handle");
        }
    };

    let sockets = ns.sockets.lock();
    let s: &tcp::Socket = sockets.get(handle);

    if s.is_active() && s.may_send() {
        drop(sockets);
        TCP_CONNECTED.store(true, Ordering::SeqCst);
        TCP_CONN_ACTIVE.store(false, Ordering::SeqCst);
        return AsyncResult::Ready(());
    }

    if !s.is_open() {
        drop(sockets);
        tcp_cleanup();
        return AsyncResult::Error("tcp connection failed");
    }

    AsyncResult::Pending
}

pub fn tcp_send(data: &[u8]) -> Result<usize, &'static str> {
    let handle = TCP_HANDLE.lock().ok_or("no tcp connection")?;
    let ns = get_network_stack().ok_or("no network")?;

    ns.poll();

    let mut sockets = ns.sockets.lock();
    let s: &mut tcp::Socket = sockets.get_mut(handle);

    if !s.may_send() {
        return Err("cannot send");
    }

    match s.send_slice(data) {
        Ok(n) => Ok(n),
        Err(_) => Err("send failed"),
    }
}

pub fn tcp_poll_receive(max_len: usize) -> AsyncResult<Vec<u8>> {
    let handle = match *TCP_HANDLE.lock() {
        Some(h) => h,
        None => return AsyncResult::Error("no tcp connection"),
    };

    let ns = match get_network_stack() {
        Some(s) => s,
        None => return AsyncResult::Error("no network"),
    };

    ns.poll();

    let mut sockets = ns.sockets.lock();
    let s: &mut tcp::Socket = sockets.get_mut(handle);

    let available = s.recv_queue();
    if available > 0 {
        let to_take = available.min(max_len);
        let mut buf = vec![0u8; to_take];
        match s.recv_slice(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return AsyncResult::Ready(buf);
            }
            Err(_) => {}
        }
    }

    if !s.may_recv() && !s.may_send() {
        return AsyncResult::Ready(Vec::new());
    }

    AsyncResult::Pending
}

pub fn tcp_is_open() -> bool {
    let handle = match *TCP_HANDLE.lock() {
        Some(h) => h,
        None => return false,
    };

    let ns = match get_network_stack() {
        Some(s) => s,
        None => return false,
    };

    let sockets = ns.sockets.lock();
    let s: &tcp::Socket = sockets.get(handle);
    s.is_open()
}

pub fn tcp_close() {
    if let Some(handle) = *TCP_HANDLE.lock() {
        if let Some(ns) = get_network_stack() {
            let mut sockets = ns.sockets.lock();
            let s: &mut tcp::Socket = sockets.get_mut(handle);
            let _ = s.close();
        }
    }
    tcp_cleanup();
}

pub(super) fn tcp_cleanup() {
    TCP_CONN_ACTIVE.store(false, Ordering::SeqCst);
    TCP_CONNECTED.store(false, Ordering::SeqCst);
}
