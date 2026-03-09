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

use alloc::vec::Vec;
use smoltcp::socket::tcp;

use super::config::get_config;
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::now_ms;

pub fn close(stack: &NetworkStack, conn_id: u32) -> Result<(), &'static str> {
    let handle = {
        let mut conns = stack.conns.lock();
        let conn = conns.get_mut(&conn_id).ok_or("connection not found")?;
        conn.closed = true;
        conn.tcp
    };

    {
        let mut sockets = stack.sockets.lock();
        let socket: &mut tcp::Socket = sockets.get_mut(handle);
        socket.close();
    }

    let cfg = get_config();
    let start = now_ms();
    let timeout_ms = cfg.timeouts.close_wait_ms;

    loop {
        stack.poll();

        let state = {
            let sockets = stack.sockets.lock();
            let socket: &tcp::Socket = sockets.get(handle);
            socket.state()
        };

        if state == tcp::State::Closed || state == tcp::State::TimeWait {
            break;
        }

        let elapsed = now_ms().saturating_sub(start);
        if elapsed >= timeout_ms {
            break;
        }

        crate::time::sleep_us(1_000);
    }

    {
        let mut conns = stack.conns.lock();
        conns.remove(&conn_id);
    }

    {
        let mut sockets = stack.sockets.lock();
        sockets.remove(handle);
    }

    crate::log::debug!("tcp: connection {} closed gracefully", conn_id);
    Ok(())
}

pub fn abort(stack: &NetworkStack, conn_id: u32) -> Result<(), &'static str> {
    let handle = {
        let mut conns = stack.conns.lock();
        let conn = conns.remove(&conn_id).ok_or("connection not found")?;
        conn.tcp
    };

    {
        let mut sockets = stack.sockets.lock();
        let socket: &mut tcp::Socket = sockets.get_mut(handle);
        socket.abort();
        sockets.remove(handle);
    }

    crate::log::debug!("tcp: connection {} aborted", conn_id);
    Ok(())
}

pub fn cleanup_stale_connections(stack: &NetworkStack) -> usize {
    let cfg = get_config();
    let now = now_ms();
    let threshold = cfg.stale_connection_timeout_ms;

    let stale_ids: Vec<u32> = {
        let conns = stack.conns.lock();
        conns
            .iter()
            .filter(|(_, conn)| {
                let age = now.saturating_sub(conn.last_activity_ms);
                age >= threshold
            })
            .map(|(id, _)| *id)
            .collect()
    };

    let count = stale_ids.len();

    for conn_id in stale_ids {
        let handle = {
            let mut conns = stack.conns.lock();
            match conns.remove(&conn_id) {
                Some(conn) => conn.tcp,
                None => continue,
            }
        };

        {
            let mut sockets = stack.sockets.lock();
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            socket.abort();
            sockets.remove(handle);
        }

        crate::log::debug!("tcp: cleaned up stale connection {}", conn_id);
    }

    count
}

pub fn get_connection_state(stack: &NetworkStack, conn_id: u32) -> Option<u8> {
    let conns = stack.conns.lock();
    let conn = conns.get(&conn_id)?;
    let sockets = stack.sockets.lock();
    let socket: &tcp::Socket = sockets.get(conn.tcp);

    let state = match socket.state() {
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
    };

    Some(state)
}

pub fn is_connection_active(stack: &NetworkStack, conn_id: u32) -> bool {
    let conns = stack.conns.lock();
    match conns.get(&conn_id) {
        Some(conn) => {
            if conn.closed {
                return false;
            }
            let sockets = stack.sockets.lock();
            let socket: &tcp::Socket = sockets.get(conn.tcp);
            socket.is_active()
        }
        None => false,
    }
}

pub fn get_active_connection_count(stack: &NetworkStack) -> usize {
    let conns = stack.conns.lock();
    let sockets = stack.sockets.lock();

    conns
        .values()
        .filter(|conn| {
            if conn.closed {
                return false;
            }
            let socket: &tcp::Socket = sockets.get(conn.tcp);
            socket.is_active()
        })
        .count()
}
