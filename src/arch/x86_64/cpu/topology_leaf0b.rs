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

use super::cpuid::cpuid_count;
use super::topology_types::CpuTopology;

pub fn detect_leaf_0b() -> Option<CpuTopology> {
    let mut topo = CpuTopology::default();
    let mut smt_count = 0u16;
    let mut core_count = 0u16;
    for subleaf in 0..4 {
        let (eax, ebx, ecx, _) = cpuid_count(0x0B, subleaf);
        let level_type = (ecx >> 8) & 0xFF;
        if level_type == 0 { break; }
        let shift = eax & 0x1F;
        let processors = (ebx & 0xFFFF) as u16;
        match level_type {
            1 => { smt_count = processors; topo.smt_width = shift as u8; }
            2 => { core_count = processors; topo.core_width = shift as u8; }
            _ => {}
        }
    }
    if smt_count == 0 && core_count == 0 { return None; }
    topo.threads_per_core = smt_count.max(1);
    topo.logical_processors = core_count.max(smt_count);
    topo.cores_per_package = if smt_count > 0 { core_count / smt_count } else { core_count }.max(1);
    topo.physical_cores = topo.cores_per_package;
    topo.packages = 1;
    Some(topo)
}
