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

use super::super::types::VmStatsSnapshot;
use super::types::VmStats;
use core::sync::atomic::Ordering;

impl VmStats {
    #[inline]
    pub fn mapped_pages(&self) -> usize {
        self.mapped_pages.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn mapped_memory(&self) -> u64 {
        self.mapped_memory.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn page_faults(&self) -> u64 {
        self.page_faults.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn tlb_flushes(&self) -> u64 {
        self.tlb_flushes.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn wx_violations(&self) -> u64 {
        self.wx_violations.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> VmStatsSnapshot {
        VmStatsSnapshot {
            mapped_pages: self.mapped_pages(),
            mapped_memory: self.mapped_memory(),
            page_faults: self.page_faults(),
            tlb_flushes: self.tlb_flushes(),
            wx_violations: self.wx_violations(),
        }
    }
}
