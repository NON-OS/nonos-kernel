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

use super::super::constants::{DEFAULT_RATE_LIMIT_PER_SEC, RATE_WINDOW_MS};
use super::super::error::NvmeError;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub struct RateLimiter {
    commands_in_window: AtomicU32,
    window_start_ticks: AtomicU64,
    limit_per_second: AtomicU32,
    enabled: bool,
}

impl RateLimiter {
    pub const fn new(limit_per_second: u32) -> Self {
        Self {
            commands_in_window: AtomicU32::new(0),
            window_start_ticks: AtomicU64::new(0),
            limit_per_second: AtomicU32::new(limit_per_second),
            enabled: limit_per_second > 0,
        }
    }

    pub fn check(&self) -> Result<(), NvmeError> {
        if !self.enabled {
            return Ok(());
        }
        let limit = self.limit_per_second.load(Ordering::Relaxed);
        if limit == 0 {
            return Ok(());
        }
        let now_ticks = Self::current_ticks();
        let window_start = self.window_start_ticks.load(Ordering::Relaxed);
        let ticks_per_window = Self::ticks_per_ms() * RATE_WINDOW_MS;
        if now_ticks.saturating_sub(window_start) >= ticks_per_window {
            self.window_start_ticks.store(now_ticks, Ordering::Relaxed);
            self.commands_in_window.store(1, Ordering::Relaxed);
            return Ok(());
        }
        let current = self.commands_in_window.fetch_add(1, Ordering::Relaxed);
        if current >= limit {
            self.commands_in_window.fetch_sub(1, Ordering::Relaxed);
            return Err(NvmeError::RateLimitExceeded);
        }
        Ok(())
    }

    pub fn set_limit(&self, limit: u32) {
        self.limit_per_second.store(limit, Ordering::Relaxed);
    }
    pub fn reset(&self) {
        self.commands_in_window.store(0, Ordering::Relaxed);
        self.window_start_ticks.store(0, Ordering::Relaxed);
    }
    pub fn current_rate(&self) -> u32 {
        self.commands_in_window.load(Ordering::Relaxed)
    }

    #[inline]
    fn current_ticks() -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { core::arch::x86_64::_rdtsc() }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            0
        }
    }
    #[inline]
    fn ticks_per_ms() -> u64 {
        2_000_000
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_RATE_LIMIT_PER_SEC)
    }
}
