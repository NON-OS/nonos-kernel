// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::stats::HardeningStats;
use super::super::types::*;
use alloc::collections::BTreeMap;
use core::sync::atomic::AtomicUsize;
use spin::{Mutex, RwLock};

pub static HARDENING_STATS: HardeningStats = HardeningStats::new();
pub(super) static MEMORY_HARDENING: MemoryHardening = MemoryHardening::new();

pub(super) struct MemoryHardening {
    pub(super) guard_pages: RwLock<BTreeMap<u64, GuardPage>>,
    pub(super) stack_canaries: RwLock<BTreeMap<u64, StackCanary>>,
    pub(super) allocation_tracker: Mutex<BTreeMap<u64, AllocationInfo>>,
    pub(super) initialized: AtomicUsize,
}

impl MemoryHardening {
    pub(super) const fn new() -> Self {
        Self {
            guard_pages: RwLock::new(BTreeMap::new()),
            stack_canaries: RwLock::new(BTreeMap::new()),
            allocation_tracker: Mutex::new(BTreeMap::new()),
            initialized: AtomicUsize::new(0),
        }
    }
}
