// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::RATE_LIMIT_WINDOW_MS;
use super::error::VirtioNetError;
use core::sync::atomic::{AtomicU64, Ordering};
#[derive(Debug)]
pub struct RateLimiter {
    max_pps: u64,
    burst_limit: u64,
    window_start: AtomicU64,
    packet_count: AtomicU64,
    violations: AtomicU64,
    total_packets: AtomicU64,
}

impl RateLimiter {
    pub const fn new(max_pps: u64, burst_limit: u64) -> Self {
        Self {
            max_pps,
            burst_limit,
            window_start: AtomicU64::new(0),
            packet_count: AtomicU64::new(0),
            violations: AtomicU64::new(0),
            total_packets: AtomicU64::new(0),
        }
    }

    pub fn check_rate_limit(&self, current_time_ms: u64) -> Result<(), VirtioNetError> {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        let window_start = self.window_start.load(Ordering::Acquire);
        if current_time_ms >= window_start + RATE_LIMIT_WINDOW_MS {
            if self
                .window_start
                .compare_exchange(
                    window_start,
                    current_time_ms,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.packet_count.store(0, Ordering::Release);
            }
        }

        let count = self.packet_count.fetch_add(1, Ordering::AcqRel);
        if count >= self.burst_limit {
            self.violations.fetch_add(1, Ordering::Relaxed);
            return Err(VirtioNetError::RateLimitExceeded);
        }

        let window_start_now = self.window_start.load(Ordering::Acquire);
        let elapsed = current_time_ms.saturating_sub(window_start_now);
        if elapsed > 0 {
            let current_rate = (count.saturating_mul(1000)) / elapsed;
            if current_rate > self.max_pps {
                self.violations.fetch_add(1, Ordering::Relaxed);
                return Err(VirtioNetError::RateLimitExceeded);
            }
        }

        Ok(())
    }

    pub fn get_violations(&self) -> u64 {
        self.violations.load(Ordering::Relaxed)
    }

    pub fn get_total_packets(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }

    pub fn get_current_count(&self) -> u64 {
        self.packet_count.load(Ordering::Relaxed)
    }

    pub fn get_max_pps(&self) -> u64 {
        self.max_pps
    }

    pub fn get_burst_limit(&self) -> u64 {
        self.burst_limit
    }

    pub fn reset(&self) {
        self.window_start.store(0, Ordering::Release);
        self.packet_count.store(0, Ordering::Release);
        self.violations.store(0, Ordering::Release);
        self.total_packets.store(0, Ordering::Release);
    }

    pub fn is_throttled(&self, current_time_ms: u64) -> bool {
        let window_start = self.window_start.load(Ordering::Acquire);

        if current_time_ms >= window_start + RATE_LIMIT_WINDOW_MS {
            return false;
        }

        let count = self.packet_count.load(Ordering::Acquire);

        if count >= self.burst_limit {
            return true;
        }

        let elapsed = current_time_ms.saturating_sub(window_start);
        if elapsed > 0 {
            let current_rate = (count.saturating_mul(1000)) / elapsed;
            if current_rate > self.max_pps {
                return true;
            }
        }

        false
    }

    pub fn get_stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            max_pps: self.max_pps,
            burst_limit: self.burst_limit,
            total_packets: self.total_packets.load(Ordering::Relaxed),
            violations: self.violations.load(Ordering::Relaxed),
            current_window_count: self.packet_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimiterStats {
    pub max_pps: u64,
    pub burst_limit: u64,
    pub total_packets: u64,
    pub violations: u64,
    pub current_window_count: u64,
}

impl RateLimiterStats {
    pub fn violation_rate_percent(&self) -> f64 {
        if self.total_packets == 0 {
            0.0
        } else {
            (self.violations as f64 / self.total_packets as f64) * 100.0
        }
    }
}

pub struct BidirectionalRateLimiter {
    pub rx: RateLimiter,
    pub tx: RateLimiter,
}

impl BidirectionalRateLimiter {
    pub const fn new(
        rx_max_pps: u64,
        rx_burst: u64,
        tx_max_pps: u64,
        tx_burst: u64,
    ) -> Self {
        Self {
            rx: RateLimiter::new(rx_max_pps, rx_burst),
            tx: RateLimiter::new(tx_max_pps, tx_burst),
        }
    }

    pub fn check_rx(&self, current_time_ms: u64) -> Result<(), VirtioNetError> {
        self.rx.check_rate_limit(current_time_ms)
    }

    pub fn check_tx(&self, current_time_ms: u64) -> Result<(), VirtioNetError> {
        self.tx.check_rate_limit(current_time_ms)
    }

    pub fn get_stats(&self) -> (RateLimiterStats, RateLimiterStats) {
        (self.rx.get_stats(), self.tx.get_stats())
    }

    pub fn reset(&self) {
        self.rx.reset();
        self.tx.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(1000, 100);
        assert_eq!(limiter.get_max_pps(), 1000);
        assert_eq!(limiter.get_burst_limit(), 100);
        assert_eq!(limiter.get_violations(), 0);
    }

    #[test]
    fn test_burst_limit() {
        let limiter = RateLimiter::new(1000, 10);

        for i in 0..10 {
            assert!(
                limiter.check_rate_limit(0).is_ok(),
                "Packet {} should be allowed",
                i
            );
        }

        assert_eq!(
            limiter.check_rate_limit(0),
            Err(VirtioNetError::RateLimitExceeded)
        );
    }

    #[test]
    fn test_window_reset() {
        let limiter = RateLimiter::new(1000, 10);

        for _ in 0..10 {
            let _ = limiter.check_rate_limit(0);
        }

        assert!(limiter.is_throttled(0));

        limiter.reset();
        assert!(!limiter.is_throttled(0));

        assert!(limiter.check_rate_limit(RATE_LIMIT_WINDOW_MS + 1).is_ok());
    }

    #[test]
    fn test_violation_counting() {
        let limiter = RateLimiter::new(1000, 5);

        for _ in 0..5 {
            let _ = limiter.check_rate_limit(0);
        }

        for _ in 0..3 {
            let _ = limiter.check_rate_limit(0);
        }

        assert_eq!(limiter.get_violations(), 3);
    }

    #[test]
    fn test_stats_snapshot() {
        let limiter = RateLimiter::new(1000, 100);

        for _ in 0..50 {
            let _ = limiter.check_rate_limit(0);
        }

        let stats = limiter.get_stats();
        assert_eq!(stats.total_packets, 50);
        assert_eq!(stats.max_pps, 1000);
    }

    #[test]
    fn test_bidirectional_limiter() {
        let limiter = BidirectionalRateLimiter::new(1000, 100, 500, 50);

        assert!(limiter.check_rx(0).is_ok());
        assert!(limiter.check_tx(0).is_ok());

        let (rx_stats, tx_stats) = limiter.get_stats();
        assert_eq!(rx_stats.total_packets, 1);
        assert_eq!(tx_stats.total_packets, 1);
    }
}
