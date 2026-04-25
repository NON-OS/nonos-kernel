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
    pub fn increment_guard_violations(&self) {
        self.guard_page_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_wx_violations(&self) {
        self.wx_violations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_stack_overflows(&self) {
        self.stack_overflows_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_heap_corruptions(&self) {
        self.heap_corruptions_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_double_frees(&self) {
        self.double_frees_prevented.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_use_after_free(&self) {
        self.use_after_free_detected.fetch_add(1, Ordering::Relaxed);
    }
}
