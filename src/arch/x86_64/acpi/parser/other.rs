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

use core::mem;
use core::ptr;

use crate::arch::x86_64::acpi::tables::{Hpet, Mcfg, McfgEntry, Srat, SIG_HPET, SIG_MCFG, SIG_SRAT};
use crate::arch::x86_64::acpi::tables::srat::*;
use crate::arch::x86_64::acpi::data::*;
use super::state::TableRegistry;

pub fn parse_hpet(registry: &mut TableRegistry) {
    if let Some(&addr) = registry.tables.get(&SIG_HPET) {
        unsafe {
            let hpet = ptr::read_volatile(addr as *const Hpet);
            if hpet.is_valid() {
                registry.data.hpet_address = Some(hpet.address());
            }
        }
    }
}

pub fn parse_mcfg(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_MCFG) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let mcfg = ptr::read_volatile(addr as *const Mcfg);
        let entry_count = mcfg.entry_count();
        let entries_ptr = (addr + mcfg.entries_offset() as u64) as *const McfgEntry;

        for i in 0..entry_count {
            let entry = ptr::read_volatile(entries_ptr.add(i));
            registry.data.pcie_segments.push(PcieSegment {
                base_address: entry.base_address, segment: entry.segment_group,
                start_bus: entry.start_bus, end_bus: entry.end_bus,
            });
        }
    }
}

pub fn parse_srat(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_SRAT) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let srat = ptr::read_volatile(addr as *const Srat);
        let srat_end = addr + srat.header.length as u64;
        let mut entry_ptr = addr + srat.entries_offset() as u64;

        while entry_ptr + 2 <= srat_end {
            let entry_type = ptr::read_volatile(entry_ptr as *const u8);
            let length = ptr::read_volatile((entry_ptr + 1) as *const u8);

            if length < 2 || entry_ptr + length as u64 > srat_end { break; }

            match entry_type {
                0 => parse_processor_affinity(registry, entry_ptr, length),
                1 => parse_memory_affinity(registry, entry_ptr, length),
                2 => parse_x2apic_affinity(registry, entry_ptr, length),
                _ => {}
            }

            entry_ptr += length as u64;
        }
    }
}

fn parse_processor_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratProcessorAffinity>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratProcessorAffinity);
        if entry.is_enabled() {
            for proc in &mut registry.data.processors {
                if proc.apic_id == entry.apic_id as u32 {
                    proc.proximity_domain = entry.proximity_domain();
                    break;
                }
            }
        }
    }
}

fn parse_memory_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratMemoryAffinity>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratMemoryAffinity);
        if entry.is_enabled() {
            registry.data.numa_regions.push(NumaMemoryRegion {
                base: entry.base_address, length: entry.length_bytes,
                proximity_domain: entry.proximity_domain,
                hot_pluggable: entry.is_hot_pluggable(), non_volatile: entry.is_non_volatile(),
            });
        }
    }
}

fn parse_x2apic_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratX2ApicAffinity>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratX2ApicAffinity);
        if entry.is_enabled() {
            for proc in &mut registry.data.processors {
                if proc.apic_id == entry.x2apic_id {
                    proc.proximity_domain = entry.proximity_domain;
                    break;
                }
            }
        }
    }
}
