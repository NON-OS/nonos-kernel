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

use super::super::state::TableRegistry;
use crate::arch::x86_64::acpi::data::NumaMemoryRegion;
use crate::arch::x86_64::acpi::tables::srat::*;

pub fn parse_memory_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratMemoryAffinity>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratMemoryAffinity);
        if entry.is_enabled() {
            registry.data.numa_regions.push(NumaMemoryRegion {
                base: entry.base_address,
                length: entry.length_bytes,
                proximity_domain: entry.proximity_domain,
                hot_pluggable: entry.is_hot_pluggable(),
                non_volatile: entry.is_non_volatile(),
            });
        }
    }
}

pub fn parse_x2apic_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratX2ApicAffinity>() as u8 {
        return;
    }
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
