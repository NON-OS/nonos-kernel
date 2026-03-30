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
pub struct VmStats {
    pub total_vm_areas: usize,
    pub address_spaces: usize,
    pub total_virtual_memory: u64,
    pub heap_usage: u64,
    pub stack_usage: u64,
    pub mmap_usage: u64,
    pub page_faults: u64,
    pub protection_faults: u64,
    pub swap_operations: u64,
    pub tlb_shootdowns: u64,
}
