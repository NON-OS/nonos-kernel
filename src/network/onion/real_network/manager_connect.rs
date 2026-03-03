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

use core::sync::atomic::{AtomicU64, Ordering};

use super::connection::AnyoneConnection;
use super::limiter::{DirectionLimiters, TokenBucket};
use super::manager_core::{timestamp_ms, AnyoneNetworkManager};
use super::types::{ConnectionState, ConnectionStats, DialOptions, TlsConnectionState};
use crate::network::ip::IpAddress;
use crate::network::onion::OnionError;
use crate::network::stack::TcpSocket;

impl AnyoneNetworkManager {
    pub fn connect_to_relay(&self, addr: IpAddress, port: u16) -> Result<u32, OnionError> {
        self.connect_to_relay_ex(addr, port, DialOptions::default())
    }

    pub fn connect_to_relay_ex(
        &self,
        addr: IpAddress,
        port: u16,
        opts: DialOptions,
    ) -> Result<u32, OnionError> {
        if let Some(mut pooled) = self.pool.take(&addr, port, timestamp_ms()) {
            if pooled.updown.is_none() && (opts.bandwidth_up_bps | opts.bandwidth_down_bps) != 0 {
                let now = timestamp_ms();
                let global = self.stats.bandwidth_limit_bytes_per_sec.load(Ordering::SeqCst);
                let up = if opts.bandwidth_up_bps == 0 { global } else { opts.bandwidth_up_bps };
                let down = if opts.bandwidth_down_bps == 0 { global } else { opts.bandwidth_down_bps };
                pooled.updown = Some(DirectionLimiters {
                    up: TokenBucket::new(up, now),
                    down: TokenBucket::new(down, now),
                });
            }
            pooled.last_activity_ms = timestamp_ms();
            let id = pooled.id;
            self.active.lock().insert(id, pooled);
            self.stats.active_connections.fetch_add(1, Ordering::SeqCst);
            return Ok(id);
        }

        let (sock, local_port) = self.direct_connect(addr, port, opts.connect_timeout_ms)?;

        let mut conn = AnyoneConnection {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            socket: sock,
            remote_addr: addr,
            remote_port: port,
            local_port,
            state: ConnectionState::Connected,
            created_at_ms: timestamp_ms(),
            last_activity_ms: timestamp_ms(),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            tls: None,
            updown: None,
        };

        if (opts.bandwidth_up_bps | opts.bandwidth_down_bps) != 0 {
            let now = timestamp_ms();
            let global = self.stats.bandwidth_limit_bytes_per_sec.load(Ordering::SeqCst);
            let up = if opts.bandwidth_up_bps == 0 { global } else { opts.bandwidth_up_bps };
            let down = if opts.bandwidth_down_bps == 0 { global } else { opts.bandwidth_down_bps };
            conn.updown = Some(DirectionLimiters {
                up: TokenBucket::new(up, now),
                down: TokenBucket::new(down, now),
            });
        }

        let id = conn.id;
        self.active.lock().insert(id, conn);
        self.stats.total_connections.fetch_add(1, Ordering::SeqCst);
        self.stats.active_connections.fetch_add(1, Ordering::SeqCst);
        Ok(id)
    }

    pub fn perform_tls_handshake_ex(
        &self,
        id: u32,
        sni: Option<&'static str>,
        alpn: Option<&'static [&'static str]>,
        min_tls_version: u16,
    ) -> Result<(), OnionError> {
        let mut map = self.active.lock();
        let conn = map.get_mut(&id).ok_or(OnionError::NetworkError)?;

        if conn.state != ConnectionState::Connected {
            return Err(OnionError::NetworkError);
        }

        conn.state = ConnectionState::TlsHandshake;
        let session = self
            .tls
            .handshake_with_opts(&conn.socket, sni, alpn, min_tls_version)?;
        conn.tls = Some(TlsConnectionState {
            handshake_complete: true,
            cipher_suite: Some(session.cipher_suite),
            protocol_version: session.protocol_version,
            traffic_secret_len: session.traffic_secret_len,
        });
        conn.state = ConnectionState::Authenticated;
        conn.last_activity_ms = timestamp_ms();
        Ok(())
    }

    pub fn perform_tls_handshake(&self, id: u32) -> Result<(), OnionError> {
        self.perform_tls_handshake_ex(id, None, None, 0x0304)
    }

    pub fn close_connection(&self, id: u32) -> Result<(), OnionError> {
        let mut map = self.active.lock();
        let mut conn = map.remove(&id).ok_or(OnionError::NetworkError)?;
        conn.state = ConnectionState::Closing;

        let now = timestamp_ms();
        let pooled = self.can_pool(&conn);
        if pooled {
            conn.last_activity_ms = now;
            self.pool.put(conn);
        } else {
            let _ = self.tcp_close(&conn.socket);
        }

        self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }

    pub fn resolve_hostname(&self, hostname: &str) -> Result<IpAddress, OnionError> {
        let ips = crate::network::dns::resolve(hostname).map_err(|_| OnionError::NetworkError)?;
        ips.into_iter().next().ok_or(OnionError::NetworkError)
    }

    pub fn get_connection_stats(&self, id: u32) -> Option<ConnectionStats> {
        let map = self.active.lock();
        map.get(&id).map(|c| ConnectionStats {
            connection_id: c.id,
            remote_addr: c.remote_addr,
            remote_port: c.remote_port,
            state: c.state,
            uptime_ms: timestamp_ms().saturating_sub(c.created_at_ms),
            bytes_sent: c.bytes_sent.load(Ordering::SeqCst),
            bytes_received: c.bytes_recv.load(Ordering::SeqCst),
            last_activity_ms: timestamp_ms().saturating_sub(c.last_activity_ms),
        })
    }

    pub(super) fn direct_connect(
        &self,
        addr: IpAddress,
        port: u16,
        connect_timeout_ms: u64,
    ) -> Result<(TcpSocket, u16), OnionError> {
        let socket = TcpSocket::new();
        let start = timestamp_ms();
        if let Some(net) = crate::network::get_network_stack() {
            while timestamp_ms().saturating_sub(start) <= connect_timeout_ms {
                let ipv4_addr = match addr {
                    crate::network::ip::IpAddress::V4(addr) => addr,
                    crate::network::ip::IpAddress::V6(_) => return Err(OnionError::NetworkError),
                };
                match net.tcp_connect(&socket, ipv4_addr, port) {
                    Ok(()) => {
                        let lp = net.get_local_port(&socket).unwrap_or(0);
                        return Ok((socket, lp));
                    }
                    Err(_) => {
                        crate::time::yield_now();
                    }
                }
            }
            self.stats.connection_failures.fetch_add(1, Ordering::SeqCst);
            Err(OnionError::Timeout)
        } else {
            Err(OnionError::NetworkError)
        }
    }

    pub(super) fn can_pool(&self, c: &AnyoneConnection) -> bool {
        matches!(c.state, ConnectionState::Authenticated)
            && c.tls.as_ref().map_or(false, |t| t.handshake_complete)
    }
}
