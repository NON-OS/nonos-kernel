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

use core::arch::asm;

pub fn cpu_id() -> usize {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }

    let aff0 = (mpidr & 0xFF) as usize;
    let aff1 = ((mpidr >> 8) & 0xFF) as usize;
    let aff2 = ((mpidr >> 16) & 0xFF) as usize;

    (aff2 << 8) | (aff1 << 4) | aff0
}

pub fn core_id() -> usize {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }
    (mpidr & 0xFF) as usize
}

pub fn cluster_id() -> usize {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }
    ((mpidr >> 8) & 0xFF) as usize
}

pub fn affinity_level(level: u32) -> u64 {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }

    match level {
        0 => mpidr & 0xFF,
        1 => (mpidr >> 8) & 0xFF,
        2 => (mpidr >> 16) & 0xFF,
        3 => (mpidr >> 32) & 0xFF,
        _ => 0,
    }
}

pub fn is_primary_core() -> bool {
    cpu_id() == 0
}

pub fn mpidr() -> u64 {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }
    mpidr
}

pub fn is_multiprocessor() -> bool {
    let mpidr: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    }
    (mpidr & (1 << 30)) == 0
}

pub fn main_id() -> u64 {
    let midr: u64;
    unsafe {
        asm!("mrs {}, midr_el1", out(reg) midr, options(nostack));
    }
    midr
}

pub fn implementer() -> u8 {
    ((main_id() >> 24) & 0xFF) as u8
}

pub fn variant() -> u8 {
    ((main_id() >> 20) & 0xF) as u8
}

pub fn architecture() -> u8 {
    ((main_id() >> 16) & 0xF) as u8
}

pub fn part_number() -> u16 {
    ((main_id() >> 4) & 0xFFF) as u16
}

pub fn revision() -> u8 {
    (main_id() & 0xF) as u8
}

#[derive(Debug, Clone, Copy)]
pub struct CpuInfo {
    pub cpu_id: usize,
    pub core_id: usize,
    pub cluster_id: usize,
    pub implementer: u8,
    pub part_number: u16,
    pub variant: u8,
    pub revision: u8,
}

impl CpuInfo {
    pub fn current() -> Self {
        Self {
            cpu_id: cpu_id(),
            core_id: core_id(),
            cluster_id: cluster_id(),
            implementer: implementer(),
            part_number: part_number(),
            variant: variant(),
            revision: revision(),
        }
    }
}
