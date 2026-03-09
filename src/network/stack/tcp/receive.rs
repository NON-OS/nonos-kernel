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
use core::cmp::min;
use smoltcp::socket::tcp;

use super::config::get_config;
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::now_ms;

pub fn receive(stack: &NetworkStack, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
    if max_len == 0 {
        return Ok(Vec::new());
    }

    let handle = {
        let conns = stack.conns.lock();
        let conn = conns.get(&conn_id).ok_or("connection not found")?;
        conn.tcp
    };

    let cfg = get_config();
    let timeout_ms = cfg.timeouts.receive_ms;
    let start = now_ms();
    let mut backoff_us = 100u64;

    loop {
        let elapsed = now_ms().saturating_sub(start);
        if elapsed >= timeout_ms {
            return Ok(Vec::new());
        }

        stack.poll();

        let result = {
            let mut sockets = stack.sockets.lock();
            let socket: &mut tcp::Socket = sockets.get_mut(handle);

            if !socket.is_active() && !socket.may_recv() {
                return Ok(Vec::new());
            }

            let available = socket.recv_queue();
            if available > 0 {
                let to_read = min(available, max_len);
                let mut buffer = vec![0u8; to_read];

                match socket.recv_slice(&mut buffer) {
                    Ok(n) if n > 0 => {
                        buffer.truncate(n);
                        Some(buffer)
                    }
                    Ok(_) => None,
                    Err(_) => {
                        return Err("receive failed");
                    }
                }
            } else if !socket.may_recv() {
                return Ok(Vec::new());
            } else {
                None
            }
        };

        if let Some(data) = result {
            let mut stats = stack.stats.lock();
            stats.rx_packets = stats.rx_packets.saturating_add(1);
            stats.rx_bytes = stats.rx_bytes.saturating_add(data.len() as u64);

            {
                let mut conns = stack.conns.lock();
                if let Some(conn) = conns.get_mut(&conn_id) {
                    conn.last_activity_ms = now_ms();
                }
            }

            return Ok(data);
        }

        crate::time::sleep_us(backoff_us);
        backoff_us = backoff_us.saturating_mul(2).min(10_000);
    }
}

pub fn receive_exact(stack: &NetworkStack, conn_id: u32, len: usize) -> Result<Vec<u8>, &'static str> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let cfg = get_config();
    let timeout_ms = cfg.timeouts.receive_ms;
    let start = now_ms();
    let mut buffer = Vec::with_capacity(len);

    while buffer.len() < len {
        let elapsed = now_ms().saturating_sub(start);
        if elapsed >= timeout_ms {
            if buffer.is_empty() {
                return Err("receive timeout");
            }
            return Ok(buffer);
        }

        let remaining = len.saturating_sub(buffer.len());
        match receive(stack, conn_id, remaining) {
            Ok(chunk) if !chunk.is_empty() => {
                buffer.extend_from_slice(&chunk);
            }
            Ok(_) => {
                if buffer.is_empty() {
                    return Err("connection closed");
                }
                return Ok(buffer);
            }
            Err(e) => {
                if buffer.is_empty() {
                    return Err(e);
                }
                return Ok(buffer);
            }
        }
    }

    Ok(buffer)
}

pub fn peek(stack: &NetworkStack, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
    let handle = {
        let conns = stack.conns.lock();
        let conn = conns.get(&conn_id).ok_or("connection not found")?;
        conn.tcp
    };

    let mut sockets = stack.sockets.lock();
    let socket: &mut tcp::Socket = sockets.get_mut(handle);

    let available = socket.recv_queue();
    if available == 0 {
        return Ok(Vec::new());
    }

    let to_peek = min(available, max_len);
    let mut buffer = vec![0u8; to_peek];

    match socket.peek_slice(&mut buffer) {
        Ok(n) => {
            buffer.truncate(n);
            Ok(buffer)
        }
        Err(_) => Err("peek failed"),
    }
}
