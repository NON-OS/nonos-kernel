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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use super::connection::AnyoneConnection;
use super::limiter::TokenBucket;
use super::pool::ConnectionPool;
use super::types::{NetworkStats, TlsProvider};
use crate::network::onion::OnionError;

pub struct AnyoneNetworkManager {
    pub(super) active: Mutex<BTreeMap<u32, AnyoneConnection>>,
    pub(super) next_id: AtomicU32,
    pub(super) stats: NetworkStats,
    pub(super) pool: ConnectionPool,
    pub(super) tls: &'static dyn TlsProvider,
    pub(super) io_timeout_ms: u64,
    pub(super) limiter: Mutex<TokenBucket>,
}

static ANYONE_NETWORK_MANAGER: Once<AnyoneNetworkManager> = Once::new();

pub fn init_anyone_network(tls: &'static dyn TlsProvider, bandwidth_limit_bps: u64) {
    let now = timestamp_ms();
    ANYONE_NETWORK_MANAGER.call_once(|| AnyoneNetworkManager {
        active: Mutex::new(BTreeMap::new()),
        next_id: AtomicU32::new(1),
        stats: NetworkStats {
            total_connections: AtomicU32::new(0),
            active_connections: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connection_failures: AtomicU32::new(0),
            bandwidth_limit_bytes_per_sec: AtomicU64::new(
                if bandwidth_limit_bps == 0 { 1_048_576 } else { bandwidth_limit_bps },
            ),
        },
        pool: ConnectionPool::new(32, 300_000),
        tls,
        io_timeout_ms: 15_000,
        limiter: Mutex::new(TokenBucket::new(
            if bandwidth_limit_bps == 0 { 1_048_576 } else { bandwidth_limit_bps },
            now,
        )),
    });
}

pub fn get_anyone_network() -> Option<&'static AnyoneNetworkManager> {
    ANYONE_NETWORK_MANAGER.get()
}

pub fn anyone_network() -> Result<&'static AnyoneNetworkManager, OnionError> {
    ANYONE_NETWORK_MANAGER.get().ok_or(OnionError::NotInitialized)
}

impl AnyoneNetworkManager {
    pub fn get_network_stats(&self) -> &NetworkStats {
        &self.stats
    }

    pub fn set_bandwidth_limit(&self, bytes_per_sec: u64) {
        self.stats
            .bandwidth_limit_bytes_per_sec
            .store(bytes_per_sec, Ordering::SeqCst);
        let now = timestamp_ms();
        let mut tb = self.limiter.lock();
        tb.set_rate(bytes_per_sec, now);
    }
}

#[inline]
pub(super) fn timestamp_ms() -> u64 {
    crate::time::timestamp_millis()
}
