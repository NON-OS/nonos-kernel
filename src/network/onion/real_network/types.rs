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


use core::sync::atomic::{AtomicU32, AtomicU64};
use crate::network::stack::TcpSocket;
use crate::network::onion::OnionError;
use crate::network::ip::IpAddress;

pub trait TlsProvider: Sync + Send {
    fn handshake_with_opts(
        &self,
        sock: &TcpSocket,
        sni: Option<&'static str>,
        alpn: Option<&'static [&'static str]>,
        min_tls_version: u16,
    ) -> Result<TlsSessionInfo, OnionError>;
}

#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub cipher_suite: u16,
    pub protocol_version: u16,
    pub traffic_secret_len: u16,
}

#[derive(Clone, Copy)]
pub struct DialOptions {
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub bandwidth_up_bps: u64,
    pub bandwidth_down_bps: u64,
    pub prefer_ipv6: bool,
    pub happy_eyeballs_ms: u64,
    pub sni: Option<&'static str>,
    pub alpn: Option<&'static [&'static str]>,
    pub min_tls_version: u16,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            read_timeout_ms: 15_000,
            write_timeout_ms: 15_000,
            bandwidth_up_bps: 0,
            bandwidth_down_bps: 0,
            prefer_ipv6: true,
            happy_eyeballs_ms: 250,
            sni: None,
            alpn: None,
            min_tls_version: 0x0304,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    TlsHandshake,
    Authenticated,
    Closing,
    Closed,
    Error,
}

#[derive(Debug, Clone)]
pub struct TlsConnectionState {
    pub handshake_complete: bool,
    pub cipher_suite: Option<u16>,
    pub protocol_version: u16,
    pub traffic_secret_len: u16,
}

#[derive(Debug)]
pub struct NetworkStats {
    pub total_connections: AtomicU32,
    pub active_connections: AtomicU32,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub connection_failures: AtomicU32,
    pub bandwidth_limit_bytes_per_sec: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub connection_id: u32,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub uptime_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_activity_ms: u64,
}
