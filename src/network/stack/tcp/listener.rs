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

use alloc::collections::BTreeMap;
use alloc::vec;
use core::sync::atomic::Ordering;
use spin::Mutex;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;

use super::config::get_config;
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::now_ms;
use crate::network::stack::types::ConnectionEntry;

struct ListenerState {
    handles: alloc::vec::Vec<SocketHandle>,
}

static LISTENERS: Mutex<BTreeMap<u16, ListenerState>> = Mutex::new(BTreeMap::new());

pub fn bind(stack: &NetworkStack, port: u16, backlog: usize) -> Result<(), &'static str> {
    if port == 0 {
        return Err("invalid port");
    }

    if backlog == 0 {
        return Err("backlog must be positive");
    }

    let effective_backlog = backlog.min(128);

    {
        let listeners = LISTENERS.lock();
        if listeners.contains_key(&port) {
            return Err("port already bound");
        }
    }

    let cfg = get_config();
    let mut handles = alloc::vec::Vec::with_capacity(effective_backlog);

    for _ in 0..effective_backlog {
        let mut sockets = stack.sockets.lock();
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.rx_buffer_size]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.tx_buffer_size]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);

        if socket.listen(port).is_err() {
            for h in handles {
                sockets.remove(h);
            }
            return Err("listen failed");
        }

        handles.push(sockets.add(socket));
    }

    {
        let mut listeners = LISTENERS.lock();
        listeners.insert(port, ListenerState { handles });
    }

    crate::log::info!("tcp: listening on port {} with backlog {}", port, effective_backlog);
    Ok(())
}

pub fn accept(stack: &NetworkStack, port: u16) -> Result<u32, &'static str> {
    let (accepted_handle, listener_idx) = {
        let listeners = LISTENERS.lock();
        let listener = listeners.get(&port).ok_or("port not listening")?;

        let sockets = stack.sockets.lock();
        let mut found = None;

        for (idx, &handle) in listener.handles.iter().enumerate() {
            let socket: &tcp::Socket = sockets.get(handle);
            if socket.is_active() && socket.may_recv() {
                found = Some((handle, idx));
                break;
            }
        }

        match found {
            Some(f) => f,
            None => return Err("no pending connections"),
        }
    };

    let cfg = get_config();

    {
        let mut listeners = LISTENERS.lock();
        let listener = listeners.get_mut(&port).ok_or("port not listening")?;

        let mut sockets = stack.sockets.lock();
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.rx_buffer_size]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; cfg.tx_buffer_size]);
        let mut new_socket = tcp::Socket::new(rx_buf, tx_buf);

        if new_socket.listen(port).is_ok() {
            let new_handle = sockets.add(new_socket);
            listener.handles[listener_idx] = new_handle;
        }
    }

    let conn_id = stack.next_id.fetch_add(1, Ordering::SeqCst);

    {
        let mut conns = stack.conns.lock();
        conns.insert(conn_id, ConnectionEntry {
            id: conn_id,
            tcp: accepted_handle,
            last_activity_ms: now_ms(),
            closed: false,
        });
    }

    crate::log::debug!("tcp: accepted connection {} on port {}", conn_id, port);
    Ok(conn_id)
}

pub fn unbind(stack: &NetworkStack, port: u16) -> Result<(), &'static str> {
    let handles = {
        let mut listeners = LISTENERS.lock();
        match listeners.remove(&port) {
            Some(listener) => listener.handles,
            None => return Err("port not bound"),
        }
    };

    {
        let mut sockets = stack.sockets.lock();
        for handle in handles {
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            socket.abort();
            sockets.remove(handle);
        }
    }

    crate::log::info!("tcp: unbound port {}", port);
    Ok(())
}

pub fn get_pending_connection_count(stack: &NetworkStack, port: u16) -> Option<usize> {
    let listeners = LISTENERS.lock();
    let listener = listeners.get(&port)?;

    let sockets = stack.sockets.lock();
    let count = listener
        .handles
        .iter()
        .filter(|&&handle| {
            let socket: &tcp::Socket = sockets.get(handle);
            socket.is_active() && socket.may_recv()
        })
        .count();

    Some(count)
}
