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

use super::super::types::{MemoryAnomaly, MemoryStats};
use super::state::MEMORY_SAFETY;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub fn check_integrity() -> Result<Vec<MemoryAnomaly>, &'static str> {
    if !MEMORY_SAFETY.is_initialized() {
        return Err("Memory safety not initialized");
    }
    Ok(MEMORY_SAFETY.analyze_patterns())
}

pub fn get_stats() -> MemoryStats {
    MemoryStats {
        violations: MEMORY_SAFETY.corruption_detector.violations.load(Ordering::Relaxed),
        protection_level: *MEMORY_SAFETY.protection_level.read(),
        regions_count: MEMORY_SAFETY.regions.read().len(),
        access_patterns: MEMORY_SAFETY.access_history.read().len(),
    }
}

pub fn last_corruption_check() -> usize {
    MEMORY_SAFETY.corruption_detector.last_check_time()
}
