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

#[derive(Debug, Clone, Default)]
pub struct PagingStats {
    pub total_mappings: usize,
    pub address_spaces: usize,
    pub page_faults: u64,
    pub tlb_flushes: u64,
    pub cow_faults: u64,
    pub demand_loads: u64,
    pub huge_pages: usize,
    pub user_pages: usize,
    pub kernel_pages: usize,
    pub page_modifications: u64,
}
