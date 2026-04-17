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

use alloc::vec::Vec;
use super::super::constants::*;
use super::super::types::*;
use super::state::kernel_sections;

pub fn get_all_stack_regions() -> Vec<StackRegion> {
    let mut regions = Vec::with_capacity((MAX_CPUS as usize) * (1 + IST_STACKS_PER_CPU));
    for cpu_id in 0..MAX_CPUS {
        let stack_base = PERCPU_BASE.saturating_add((cpu_id as u64).saturating_mul(PERCPU_STRIDE));
        regions.push(StackRegion { base: stack_base, size: KSTACK_SIZE, guard_size: GUARD_PAGES * PAGE_SIZE, cpu_id: Some(cpu_id), thread_id: None });
        for ist_num in 0..IST_STACKS_PER_CPU {
            let ist_offset = (KSTACK_SIZE as u64).saturating_add((ist_num as u64).saturating_mul(IST_STACK_SIZE as u64));
            regions.push(StackRegion { base: stack_base.saturating_add(ist_offset), size: IST_STACK_SIZE, guard_size: GUARD_PAGES * PAGE_SIZE, cpu_id: Some(cpu_id), thread_id: None });
        }
    }
    regions
}

pub fn get_percpu_regions() -> Vec<PercpuRegion> {
    let mut regions = Vec::with_capacity(MAX_CPUS as usize);
    for cpu_id in 0..MAX_CPUS {
        let base = PERCPU_BASE.saturating_add((cpu_id as u64).saturating_mul(PERCPU_STRIDE));
        regions.push(PercpuRegion { base, size: PERCPU_STRIDE as usize, cpu_id });
    }
    regions
}

pub fn get_percpu_region_for(cpu_id: u32) -> Option<PercpuRegion> {
    if cpu_id >= MAX_CPUS { return None; }
    let base = PERCPU_BASE.saturating_add((cpu_id as u64).saturating_mul(PERCPU_STRIDE));
    Some(PercpuRegion { base, size: PERCPU_STRIDE as usize, cpu_id })
}

pub fn get_module_regions() -> Vec<ModuleRegion> {
    let mut regions = Vec::with_capacity(KERNEL_SECTION_COUNT);
    for section in kernel_sections().iter() {
        let mut perms = 0u32;
        if section.rx || !section.nx { perms |= PERM_READ; }
        if section.rw { perms |= PERM_WRITE; }
        if section.rx || !section.nx { perms |= PERM_EXEC; }
        regions.push(ModuleRegion { base: section.start, size: section.size() as usize, name: "kernel", permissions: perms });
    }
    regions
}
