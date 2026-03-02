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


pub const MAX_NUMA_NODES: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    pub logical_cpus: usize,
    pub physical_cores: usize,
    pub numa_nodes: usize,
    pub hyperthreading: bool,
    pub x2apic: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuInfo {
    pub apic_id: u32,
    pub package_id: u32,
    pub core_id: u32,
    pub smt_id: u32,
    pub numa_node: u32,
}
