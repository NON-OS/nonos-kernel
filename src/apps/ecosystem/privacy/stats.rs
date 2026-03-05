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

//! Privacy statistics tracking.

use core::sync::atomic::{AtomicU64, Ordering};

static REQUESTS_BLOCKED: AtomicU64 = AtomicU64::new(0);
static REQUESTS_ALLOWED: AtomicU64 = AtomicU64::new(0);
static PARAMS_STRIPPED: AtomicU64 = AtomicU64::new(0);
static FINGERPRINT_BLOCKED: AtomicU64 = AtomicU64::new(0);
static COOKIES_BLOCKED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub struct PrivacyStats {
    pub requests_blocked: u64,
    pub requests_allowed: u64,
    pub params_stripped: u64,
    pub fingerprint_blocked: u64,
    pub cookies_blocked: u64,
}

impl PrivacyStats {
    pub fn total_requests(&self) -> u64 {
        self.requests_blocked + self.requests_allowed
    }

    pub fn block_rate(&self) -> f32 {
        let total = self.total_requests();
        if total == 0 {
            return 0.0;
        }
        (self.requests_blocked as f32 / total as f32) * 100.0
    }
}

pub fn get_stats() -> PrivacyStats {
    PrivacyStats {
        requests_blocked: REQUESTS_BLOCKED.load(Ordering::Relaxed),
        requests_allowed: REQUESTS_ALLOWED.load(Ordering::Relaxed),
        params_stripped: PARAMS_STRIPPED.load(Ordering::Relaxed),
        fingerprint_blocked: FINGERPRINT_BLOCKED.load(Ordering::Relaxed),
        cookies_blocked: COOKIES_BLOCKED.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    REQUESTS_BLOCKED.store(0, Ordering::Relaxed);
    REQUESTS_ALLOWED.store(0, Ordering::Relaxed);
    PARAMS_STRIPPED.store(0, Ordering::Relaxed);
    FINGERPRINT_BLOCKED.store(0, Ordering::Relaxed);
    COOKIES_BLOCKED.store(0, Ordering::Relaxed);
}

pub fn increment_blocked() {
    REQUESTS_BLOCKED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_allowed() {
    REQUESTS_ALLOWED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_params_stripped() {
    PARAMS_STRIPPED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_fingerprint_blocked() {
    FINGERPRINT_BLOCKED.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_cookies_blocked() {
    COOKIES_BLOCKED.fetch_add(1, Ordering::Relaxed);
}
