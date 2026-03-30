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

use core::sync::atomic::{AtomicU64, AtomicUsize};

pub struct VmStats {
    pub(super) mapped_pages: AtomicUsize,
    pub(super) mapped_memory: AtomicU64,
    pub(super) page_faults: AtomicU64,
    pub(super) tlb_flushes: AtomicU64,
    pub(super) wx_violations: AtomicU64,
}

impl VmStats {
    pub const fn new() -> Self {
        Self {
            mapped_pages: AtomicUsize::new(0),
            mapped_memory: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            tlb_flushes: AtomicU64::new(0),
            wx_violations: AtomicU64::new(0),
        }
    }
}
