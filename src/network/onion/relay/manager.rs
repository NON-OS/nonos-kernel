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

//! Relay manager for OR link management

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::network::tcp::TcpSocket;
use crate::network::onion::cell::Cell;
use crate::network::onion::directory::RelayDescriptor;
use crate::network::onion::OnionError;

use super::connection::ORConnection;
use super::types::{LinkId, RelayConfig};

/// Statistics for relay operations
#[derive(Debug, Default)]
pub struct RelayStats {
    pub links_opened: AtomicU64,
    pub links_closed: AtomicU64,
    pub cells_tx: AtomicU64,
    pub cells_rx: AtomicU64,
}

/// Bandwidth limiter state
pub struct BandwidthLimiter {
    /// Maximum bytes per second (0 = unlimited)
    rate_limit: AtomicU64,
    /// Maximum burst size (0 = unlimited)
    burst_limit: AtomicU64,
    /// Tokens available for current burst
    tokens: AtomicU64,
    /// Last token refill time (milliseconds)
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

    /// Set bandwidth limits
    pub fn set_limits(&self, rate: u64, burst: u64) {
        self.rate_limit.store(rate, Ordering::SeqCst);
        self.burst_limit.store(burst, Ordering::SeqCst);
        self.tokens.store(burst, Ordering::SeqCst);
        self.last_refill.store(crate::time::timestamp_millis(), Ordering::SeqCst);
    }

    /// Check if sending bytes is allowed (token bucket)
    pub fn allow_bytes(&self, bytes: u64) -> bool {
        let rate = self.rate_limit.load(Ordering::Relaxed);
        if rate == 0 {
            return true; // Unlimited
        }

        // Refill tokens based on elapsed time
        let now = crate::time::timestamp_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);

        if elapsed_ms > 0 {
            // Tokens per millisecond = rate / 1000
            let new_tokens = (rate * elapsed_ms) / 1000;
            let burst = self.burst_limit.load(Ordering::Relaxed);
            let current = self.tokens.load(Ordering::Relaxed);
            let refilled = core::cmp::min(current.saturating_add(new_tokens), burst);
            self.tokens.store(refilled, Ordering::Relaxed);
            self.last_refill.store(now, Ordering::Relaxed);
        }

        // Try to consume tokens
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

/// Manager for OR link connections
pub struct RelayManager {
    links: Mutex<BTreeMap<LinkId, Box<ORConnection>>>,
    next_id: AtomicU64,
    stats: RelayStats,
    /// Current relay configuration (if running as relay)
    config: Mutex<Option<RelayConfig>>,
    /// Whether relay mode is active
    relay_active: AtomicBool,
    /// Bandwidth limiter for rate limiting
    bandwidth: BandwidthLimiter,
}

impl RelayManager {
    /// Create new relay manager
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

    /// Configure the relay with the given settings
    ///
    /// This sets up the relay manager to operate as an Anyone relay,
    /// accepting incoming connections and forwarding traffic.
    pub fn configure(&mut self, config: RelayConfig) -> Result<(), OnionError> {
        // Validate the configuration
        if config.nickname.is_empty() {
            return Err(OnionError::InvalidConfig);
        }

        if config.or_port == 0 {
            return Err(OnionError::InvalidConfig);
        }

        // Set bandwidth limits if configured
        if config.bandwidth_rate > 0 {
            self.bandwidth.set_limits(config.bandwidth_rate, config.bandwidth_burst);
        }

        // Store configuration
        *self.config.lock() = Some(config);
        self.relay_active.store(true, Ordering::SeqCst);

        crate::log::info!("relay: configured and active");
        Ok(())
    }

    /// Set bandwidth limits (bytes per second)
    ///
    /// - `rate`: Maximum sustained bandwidth in bytes per second (0 = unlimited)
    /// - `burst`: Maximum burst size in bytes (typically 2x rate)
    pub fn set_bandwidth_limit(&self, rate: u64, burst: u64) {
        self.bandwidth.set_limits(rate, burst);
        crate::log::info!("relay: bandwidth limit set to {} B/s (burst {})", rate, burst);
    }

    /// Shutdown the relay, closing all connections
    pub fn shutdown(&mut self) -> Result<(), OnionError> {
        // Mark relay as inactive
        self.relay_active.store(false, Ordering::SeqCst);

        // Close all links
        let mut guard = self.links.lock();
        let link_count = guard.len();
        guard.clear();

        // Clear configuration
        *self.config.lock() = None;

        crate::log::info!("relay: shutdown complete, closed {} links", link_count);
        Ok(())
    }

    /// Check if relay mode is active
    pub fn is_active(&self) -> bool {
        self.relay_active.load(Ordering::Relaxed)
    }

    /// Get current relay configuration
    pub fn get_config(&self) -> Option<RelayConfig> {
        self.config.lock().clone()
    }

    /// Check bandwidth before sending data
    pub fn check_bandwidth(&self, bytes: u64) -> bool {
        self.bandwidth.allow_bytes(bytes)
    }

    /// Allocate a new link ID
    fn alloc_id(&self) -> LinkId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a new connection and perform TLS handshake
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

    /// Send a cell on a specific link
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

    /// Poll all links for incoming cells
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

        // Remove dead links
        if !dead.is_empty() {
            let mut guard = self.links.lock();
            for id in dead {
                guard.remove(&id);
                self.stats.links_closed.fetch_add(1, Ordering::Relaxed);
            }
        }

        total
    }

    /// Close a specific link
    pub fn close_link(&self, link: LinkId) {
        let mut guard = self.links.lock();
        if guard.remove(&link).is_some() {
            self.stats.links_closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get number of active links
    pub fn link_count(&self) -> usize {
        self.links.lock().len()
    }

    /// Get relay statistics
    pub fn get_stats(&self) -> &RelayStats {
        &self.stats
    }
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}
