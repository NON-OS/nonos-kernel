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

use smoltcp::socket::tcp;

use super::config::get_config;
use crate::network::stack::core::NetworkStack;
use crate::network::stack::device::now_ms;

pub fn send(stack: &NetworkStack, conn_id: u32, data: &[u8]) -> Result<usize, &'static str> {
    use crate::sys::serial;

    if data.is_empty() {
        return Ok(0);
    }

    let handle = {
        let mut conns = stack.conns.lock();
        let conn = match conns.get_mut(&conn_id) {
            Some(c) => c,
            None => {
                serial::print(b"[TCP] send: conn not found id=");
                serial::print_dec(conn_id as u64);
                serial::println(b"");
                return Err("connection not found");
            }
        };
        if conn.closed {
            serial::println(b"[TCP] send: connection closed");
            return Err("connection closed");
        }
        conn.last_activity_ms = now_ms();
        conn.tcp
    };

    let cfg = get_config();
    let timeout_ms = cfg.timeouts.send_ms;
    let start = now_ms();
    let mut total_sent = 0usize;
    let mut consecutive_zero_sends = 0u32;
    let mut backoff_us = 100u64;

    while total_sent < data.len() {
        let elapsed = now_ms().saturating_sub(start);
        if elapsed >= timeout_ms {
            serial::print(b"[TCP] send timeout after ");
            serial::print_dec(elapsed);
            serial::println(b"ms");
            if total_sent > 0 {
                return Ok(total_sent);
            }
            return Err("send timeout");
        }

        stack.poll();

        let sent_this_round = {
            let mut sockets = stack.sockets.lock();
            let socket: &mut tcp::Socket = sockets.get_mut(handle);

            if !socket.is_active() {
                serial::println(b"[TCP] send: socket not active");
                if total_sent > 0 {
                    return Ok(total_sent);
                }
                return Err("connection reset");
            }

            if !socket.may_send() {
                serial::println(b"[TCP] send: socket may_send=false");
                0
            } else {
                match socket.send_slice(&data[total_sent..]) {
                    Ok(n) => n,
                    Err(_) => {
                        if total_sent > 0 {
                            return Ok(total_sent);
                        }
                        return Err("send failed");
                    }
                }
            }
        };

        if sent_this_round > 0 {
            total_sent = total_sent.saturating_add(sent_this_round);
            consecutive_zero_sends = 0;
            backoff_us = 100;

            let mut stats = stack.stats.lock();
            stats.tx_packets = stats.tx_packets.saturating_add(1);
            stats.tx_bytes = stats.tx_bytes.saturating_add(sent_this_round as u64);
        } else {
            consecutive_zero_sends = consecutive_zero_sends.saturating_add(1);

            if consecutive_zero_sends > 1000 {
                if total_sent > 0 {
                    return Ok(total_sent);
                }
                return Err("send buffer full");
            }

            crate::time::sleep_us(backoff_us);
            backoff_us = backoff_us.saturating_mul(2).min(10_000);
        }
    }

    Ok(total_sent)
}
