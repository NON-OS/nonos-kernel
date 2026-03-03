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


use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::network::tcp::TcpSocket;
use crate::network::onion::cell::Cell;
use crate::network::onion::directory::RelayDescriptor;
use crate::network::onion::OnionError;

use super::connection::ORConnection;
use super::types::{LinkId, RelayConfig};

#[derive(Debug, Default)]
pub struct RelayStats {
    pub links_opened: AtomicU64,
    pub links_closed: AtomicU64,
    pub cells_tx: AtomicU64,
    pub cells_rx: AtomicU64,
}

pub struct BandwidthLimiter {
    rate_limit: AtomicU64,
    burst_limit: AtomicU64,
    tokens: AtomicU64,
    last_refill: AtomicU64,
}

impl BandwidthLimiter {
    pub fn new() -> Self {
        Self {
            rate_limit: AtomicU64::new(0),
            burst_limit: AtomicU64::new(0),
            tokens: AtomicU64::new(0),
            last_refill: AtomicU64::new(0),
        }
    }

    pub fn set_limits(&self, rate: u64, burst: u64) {
        self.rate_limit.store(rate, Ordering::SeqCst);
        self.burst_limit.store(burst, Ordering::SeqCst);
        self.tokens.store(burst, Ordering::SeqCst);
        self.last_refill.store(crate::time::timestamp_millis(), Ordering::SeqCst);
    }

    pub fn allow_bytes(&self, bytes: u64) -> bool {
        let rate = self.rate_limit.load(Ordering::Relaxed);
        if rate == 0 {
            return true;
        }

        let now = crate::time::timestamp_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);

        if elapsed_ms > 0 {
            let new_tokens = (rate * elapsed_ms) / 1000;
            let burst = self.burst_limit.load(Ordering::Relaxed);
            let current = self.tokens.load(Ordering::Relaxed);
            let refilled = core::cmp::min(current.saturating_add(new_tokens), burst);
            self.tokens.store(refilled, Ordering::Relaxed);
            self.last_refill.store(now, Ordering::Relaxed);
        }

        let current = self.tokens.load(Ordering::Relaxed);
        if current >= bytes {
            self.tokens.store(current - bytes, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl Default for BandwidthLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RelayManager {
    links: Mutex<BTreeMap<LinkId, Box<ORConnection>>>,
    next_id: AtomicU64,
    stats: RelayStats,
    config: Mutex<Option<RelayConfig>>,
    relay_active: AtomicBool,
    bandwidth: BandwidthLimiter,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            links: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            stats: RelayStats::default(),
            config: Mutex::new(None),
            relay_active: AtomicBool::new(false),
            bandwidth: BandwidthLimiter::new(),
        }
    }

    pub fn configure(&mut self, config: RelayConfig) -> Result<(), OnionError> {
        if config.nickname.is_empty() {
            return Err(OnionError::InvalidConfig);
        }

        if config.or_port == 0 {
            return Err(OnionError::InvalidConfig);
        }

        if config.bandwidth_rate > 0 {
            self.bandwidth.set_limits(config.bandwidth_rate, config.bandwidth_burst);
        }

        *self.config.lock() = Some(config);
        self.relay_active.store(true, Ordering::SeqCst);

        crate::log::info!("relay: configured and active");
        Ok(())
    }

    pub fn set_bandwidth_limit(&self, rate: u64, burst: u64) {
        self.bandwidth.set_limits(rate, burst);
        crate::log::info!("relay: bandwidth limit set to {} B/s (burst {})", rate, burst);
    }

    pub fn shutdown(&mut self) -> Result<(), OnionError> {
        self.relay_active.store(false, Ordering::SeqCst);

        let mut guard = self.links.lock();
        let link_count = guard.len();
        guard.clear();

        *self.config.lock() = None;

        crate::log::info!("relay: shutdown complete, closed {} links", link_count);
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.relay_active.load(Ordering::Relaxed)
    }

    pub fn get_config(&self) -> Option<RelayConfig> {
        self.config.lock().clone()
    }

    pub fn check_bandwidth(&self, bytes: u64) -> bool {
        self.bandwidth.allow_bytes(bytes)
    }

    fn alloc_id(&self) -> LinkId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn register_and_handshake(
        &self,
        sock: TcpSocket,
        peer: RelayDescriptor,
    ) -> Result<LinkId, OnionError> {
        let mut conn = ORConnection::new(sock, peer);
        conn.handshake()?;
        let id = self.alloc_id();
        self.links.lock().insert(id, Box::new(conn));
        self.stats.links_opened.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    pub fn send_cell(&self, link: LinkId, cell: &Cell) -> Result<(), OnionError> {
        let mut guard = self.links.lock();
        if let Some(conn) = guard.get_mut(&link) {
            conn.send_cell(cell)?;
            self.stats.cells_tx.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(OnionError::NetworkError)
        }
    }

    pub fn poll<F: FnMut(Cell)>(&self, mut on_cell: F) -> usize {
        let mut total = 0usize;
        let mut dead: Vec<LinkId> = Vec::new();

        {
            let mut guard = self.links.lock();
            for (id, conn) in guard.iter_mut() {
                match conn.poll_read(|c| on_cell(c)) {
                    Ok(n) => {
                        if n > 0 {
                            self.stats.cells_rx.fetch_add(n as u64, Ordering::Relaxed);
                            total += n;
                        }
                    }
                    Err(OnionError::Timeout) => {}
                    Err(e) => {
                        crate::log_warn!("relay: link {} closed due to error: {:?}", id, e);
                        dead.push(*id);
                    }
                }
            }
        }

        if !dead.is_empty() {
            let mut guard = self.links.lock();
            for id in dead {
                guard.remove(&id);
                self.stats.links_closed.fetch_add(1, Ordering::Relaxed);
            }
        }

        total
    }

    pub fn close_link(&self, link: LinkId) {
        let mut guard = self.links.lock();
        if guard.remove(&link).is_some() {
            self.stats.links_closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn link_count(&self) -> usize {
        self.links.lock().len()
    }

    pub fn get_stats(&self) -> &RelayStats {
        &self.stats
    }
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}
