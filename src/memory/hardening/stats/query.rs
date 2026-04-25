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

use super::types::HardeningStats;
use core::sync::atomic::Ordering;

impl HardeningStats {
    pub fn guard_violations(&self) -> u64 {
        self.guard_page_violations.load(Ordering::Relaxed)
    }

    pub fn wx_violations(&self) -> u64 {
        self.wx_violations.load(Ordering::Relaxed)
    }

    pub fn stack_overflows(&self) -> u64 {
        self.stack_overflows_detected.load(Ordering::Relaxed)
    }

    pub fn heap_corruptions(&self) -> u64 {
        self.heap_corruptions_detected.load(Ordering::Relaxed)
    }

    pub fn double_frees(&self) -> u64 {
        self.double_frees_prevented.load(Ordering::Relaxed)
    }

    pub fn use_after_free(&self) -> u64 {
        self.use_after_free_detected.load(Ordering::Relaxed)
    }
}
