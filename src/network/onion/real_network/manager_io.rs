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
use core::sync::atomic::Ordering;

use super::manager_core::{timestamp_ms, AnyoneNetworkManager};
use super::types::ConnectionState;
use crate::network::onion::OnionError;
use crate::network::stack::TcpSocket;

impl AnyoneNetworkManager {
    pub fn send_data(&self, id: u32, buf: &[u8]) -> Result<usize, OnionError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let now = timestamp_ms();
        {
            let mut limiter = self.limiter.lock();
            if !limiter.try_consume(buf.len() as u64, now) {
                return Err(OnionError::RateLimited);
            }
        }

        let timeout = self.io_timeout_ms;
        let mut map = self.active.lock();
        let conn = map.get_mut(&id).ok_or(OnionError::NetworkError)?;
        if conn.state != ConnectionState::Connected && conn.state != ConnectionState::Authenticated {
            return Err(OnionError::NetworkError);
        }

        if let Some(lims) = conn.updown.as_mut() {
            if !lims.up.try_consume(buf.len() as u64, now) {
                return Err(OnionError::RateLimited);
            }
        }

        let n = self.tcp_write_all(&conn.socket, buf, timeout)?;
        conn.bytes_sent.fetch_add(n as u64, Ordering::SeqCst);
        conn.last_activity_ms = timestamp_ms();
        self.stats.bytes_sent.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    pub fn receive_data(&self, id: u32, dst: &mut [u8]) -> Result<usize, OnionError> {
        if dst.is_empty() {
            return Ok(0);
        }
        let timeout = self.io_timeout_ms;
        let mut map = self.active.lock();
        let conn = map.get_mut(&id).ok_or(OnionError::NetworkError)?;
        if conn.state != ConnectionState::Connected && conn.state != ConnectionState::Authenticated {
            return Err(OnionError::NetworkError);
        }

        let n = self.tcp_read_some(&conn.socket, dst, timeout)?;
        if n > 0 {
            if let Some(lims) = conn.updown.as_mut() {
                let now = timestamp_ms();
                if !lims.down.try_consume(n as u64, now) {
                    return Err(OnionError::RateLimited);
                }
            }
            conn.bytes_recv.fetch_add(n as u64, Ordering::SeqCst);
            conn.last_activity_ms = timestamp_ms();
            self.stats.bytes_received.fetch_add(n as u64, Ordering::SeqCst);
        }
        Ok(n)
    }

    pub fn cleanup(&self) {
        let now = timestamp_ms();
        {
            let mut map = self.active.lock();
            let to_drop: Vec<u32> = map
                .iter()
                .filter(|(_, c)| {
                    (now.saturating_sub(c.last_activity_ms) > 300_000)
                        || (matches!(c.state, ConnectionState::Error | ConnectionState::Closed))
                })
                .map(|(id, _)| *id)
                .collect();

            for id in to_drop {
                if let Some(conn) = map.remove(&id) {
                    let _ = self.tcp_close(&conn.socket);
                    self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
        self.pool.evict_idle(now);
    }

    pub(super) fn tcp_write_all(
        &self,
        socket: &TcpSocket,
        mut buf: &[u8],
        timeout_ms: u64,
    ) -> Result<usize, OnionError> {
        let mut written = 0usize;
        let start = timestamp_ms();
        if let Some(net) = crate::network::get_network_stack() {
            while !buf.is_empty() {
                if timestamp_ms().saturating_sub(start) > timeout_ms {
                    return Err(OnionError::Timeout);
                }
                match net.tcp_send(socket.connection_id(), buf) {
                    Ok(n) if n > 0 => {
                        written += n;
                        buf = &buf[n..];
                    }
                    Ok(_) => {
                        crate::time::yield_now();
                    }
                    Err(_) => return Err(OnionError::NetworkError),
                }
            }
            Ok(written)
        } else {
            Err(OnionError::NetworkError)
        }
    }

    pub(super) fn tcp_read_some(
        &self,
        socket: &TcpSocket,
        dst: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, OnionError> {
        let start = timestamp_ms();
        if let Some(net) = crate::network::get_network_stack() {
            loop {
                if timestamp_ms().saturating_sub(start) > timeout_ms {
                    return Err(OnionError::Timeout);
                }
                match net.tcp_receive(socket.connection_id(), dst.len()) {
                    Ok(data) => {
                        let n = min(dst.len(), data.len());
                        if n == 0 {
                            if net.tcp_is_closed(socket.connection_id()).unwrap_or(false) {
                                return Ok(0);
                            }
                            crate::time::yield_now();
                            continue;
                        }
                        dst[..n].copy_from_slice(&data[..n]);
                        return Ok(n);
                    }
                    Err(_) => {
                        crate::time::yield_now();
                    }
                }
            }
        } else {
            Err(OnionError::NetworkError)
        }
    }

    pub(super) fn tcp_close(&self, socket: &TcpSocket) -> Result<(), OnionError> {
        if let Some(net) = crate::network::get_network_stack() {
            net.tcp_close(socket.connection_id()).map_err(|_| OnionError::NetworkError)
        } else {
            Err(OnionError::NetworkError)
        }
    }
}
