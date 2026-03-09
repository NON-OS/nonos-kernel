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

use spin::Mutex;

#[derive(Debug, Clone, Copy)]
pub struct TcpTimeouts {
    pub connect_ms: u64,
    pub send_ms: u64,
    pub receive_ms: u64,
    pub keepalive_ms: u64,
    pub close_wait_ms: u64,
    pub retransmit_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpConfig {
    pub timeouts: TcpTimeouts,
    pub rx_buffer_size: usize,
    pub tx_buffer_size: usize,
    pub max_connections: usize,
    pub max_retries: u8,
    pub nagle_enabled: bool,
    pub window_scale: u8,
    pub mss: u16,
    pub stale_connection_timeout_ms: u64,
}

pub(crate) static TCP_CONFIG: Mutex<TcpConfig> = Mutex::new(DEFAULT_TCP_CONFIG);

pub const DEFAULT_TCP_CONFIG: TcpConfig = TcpConfig {
    timeouts: TcpTimeouts {
        connect_ms: 30_000,
        send_ms: 30_000,
        receive_ms: 30_000,
        keepalive_ms: 7_200_000,
        close_wait_ms: 60_000,
        retransmit_ms: 1_000,
    },
    rx_buffer_size: 65536,
    tx_buffer_size: 65536,
    max_connections: 1024,
    max_retries: 5,
    nagle_enabled: false,
    window_scale: 7,
    mss: 1460,
    stale_connection_timeout_ms: 120_000,
};

pub fn get_config() -> TcpConfig {
    *TCP_CONFIG.lock()
}

pub fn set_timeouts(timeouts: TcpTimeouts) {
    let mut cfg = TCP_CONFIG.lock();
    cfg.timeouts = timeouts;
}

pub fn set_buffer_sizes(rx: usize, tx: usize) {
    let mut cfg = TCP_CONFIG.lock();
    cfg.rx_buffer_size = rx.clamp(4096, 1_048_576);
    cfg.tx_buffer_size = tx.clamp(4096, 1_048_576);
}
