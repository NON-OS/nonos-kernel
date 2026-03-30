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

#[derive(Debug)]
pub struct HardeningStatsSnapshot {
    pub guard_violations: u64,
    pub wx_violations: u64,
    pub stack_overflows: u64,
    pub heap_corruptions: u64,
    pub double_frees: u64,
    pub use_after_free: u64,
    pub total_guard_pages: usize,
    pub active_canaries: usize,
    pub tracked_allocations: usize,
}
