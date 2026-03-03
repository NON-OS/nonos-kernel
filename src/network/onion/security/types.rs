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


use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64};
use spin::Mutex;
use crate::network::onion::CircuitId;

pub(super) struct RateLimiter {
    pub ip: [u8; 4],
    pub cells_this_second: AtomicU32,
    pub last_reset: AtomicU64,
    pub violations: AtomicU32,
}

pub(super) struct TimingAttackDetector {
    pub cell_timings: Mutex<BTreeMap<CircuitId, Vec<u64>>>,
    pub correlation_threshold: f32,
}

impl TimingAttackDetector {
    pub(super) fn new() -> Self {
        TimingAttackDetector {
            cell_timings: Mutex::new(BTreeMap::new()),
            correlation_threshold: 0.7,
        }
    }
}

pub(super) struct MemoryProtector {
    pub allocations: Mutex<BTreeMap<usize, AllocInfo>>,
    pub canary_seed: u64,
}

impl MemoryProtector {
    pub(super) fn new() -> Self {
        MemoryProtector {
            allocations: Mutex::new(BTreeMap::new()),
            canary_seed: crate::crypto::entropy::rand_u64(),
        }
    }

    pub(super) fn generate_canary(&self) -> u64 {
        use alloc::vec::Vec;
        use crate::crypto::hash;

        let mut data = Vec::new();
        data.extend_from_slice(&self.canary_seed.to_le_bytes());
        data.extend_from_slice(&crate::crypto::entropy::rand_u64().to_le_bytes());
        data.extend_from_slice(&super::manager::get_timestamp().to_le_bytes());
        hash::blake3_hash(&data)[..8].try_into()
            .map(u64::from_le_bytes)
            .unwrap_or(0xDEADBEEFCAFEBABE)
    }
}

pub(super) struct AllocInfo {
    pub size: usize,
    pub canary: u64,
    pub allocated_at: u64,
}

pub struct SecurityStats {
    pub blocked_ips: AtomicU32,
    pub timing_attacks_detected: AtomicU32,
    pub rate_limit_violations: AtomicU32,
    pub memory_violations: AtomicU32,
}

impl SecurityStats {
    pub fn new() -> Self {
        SecurityStats {
            blocked_ips: AtomicU32::new(0),
            timing_attacks_detected: AtomicU32::new(0),
            rate_limit_violations: AtomicU32::new(0),
            memory_violations: AtomicU32::new(0),
        }
    }
}
