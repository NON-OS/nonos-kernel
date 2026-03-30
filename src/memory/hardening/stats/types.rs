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

use core::sync::atomic::AtomicU64;

pub struct HardeningStats {
    pub guard_page_violations: AtomicU64,
    pub wx_violations: AtomicU64,
    pub stack_overflows_detected: AtomicU64,
    pub heap_corruptions_detected: AtomicU64,
    pub double_frees_prevented: AtomicU64,
    pub use_after_free_detected: AtomicU64,
    pub mapped_file_pages: AtomicU64,
    pub total_mapped_size: AtomicU64,
    pub kernel_mappings: AtomicU64,
}

impl HardeningStats {
    pub const fn new() -> Self {
        Self {
            guard_page_violations: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
            stack_overflows_detected: AtomicU64::new(0),
            heap_corruptions_detected: AtomicU64::new(0),
            double_frees_prevented: AtomicU64::new(0),
            use_after_free_detected: AtomicU64::new(0),
            mapped_file_pages: AtomicU64::new(0),
            total_mapped_size: AtomicU64::new(0),
            kernel_mappings: AtomicU64::new(0),
        }
    }
}

impl Default for HardeningStats {
    fn default() -> Self {
        Self::new()
    }
}
