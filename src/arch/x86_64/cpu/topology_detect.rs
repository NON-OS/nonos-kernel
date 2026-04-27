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

use super::cpuid::{cpuid, cpuid_count, cpuid_max_leaf};
use super::topology_leaf0b::detect_leaf_0b;
use super::topology_types::CpuTopology;

impl CpuTopology {
    pub fn detect() -> Self {
        let mut topo = Self::default();
        let max_leaf = cpuid_max_leaf();
        if max_leaf >= 0x0B {
            if let Some(t) = detect_leaf_0b() {
                return t;
            }
        }
        let (_, ebx, _, _) = cpuid(1);
        let logical_per_package = ((ebx >> 16) & 0xFF) as u16;
        if max_leaf >= 4 {
            let (eax, _, _, _) = cpuid_count(4, 0);
            let cores_per_package = (((eax >> 26) & 0x3F) + 1) as u16;
            topo.cores_per_package = cores_per_package;
            topo.logical_processors = logical_per_package.max(1);
            topo.threads_per_core =
                if cores_per_package > 0 { logical_per_package / cores_per_package } else { 1 }
                    .max(1);
            topo.physical_cores = cores_per_package;
            topo.packages = 1;
        } else {
            topo.logical_processors = logical_per_package.max(1);
            topo.cores_per_package = 1;
            topo.threads_per_core = logical_per_package.max(1);
            topo.physical_cores = 1;
            topo.packages = 1;
        }
        topo
    }
}
