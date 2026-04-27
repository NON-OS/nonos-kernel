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

use super::super::{secure_memory as memory, virt, virtual_memory};

#[derive(Debug)]
pub struct UnifiedVmStats {
    pub virt_stats: virt::VmStatsSnapshot,
    pub vmem_stats: virtual_memory::VmStats,
    pub memory_stats: memory::ManagerStats,
}

pub fn get_unified_vm_stats() -> UnifiedVmStats {
    UnifiedVmStats {
        virt_stats: virt::get_stats(),
        vmem_stats: virtual_memory::get_vm_stats(),
        memory_stats: memory::get_memory_stats(),
    }
}
