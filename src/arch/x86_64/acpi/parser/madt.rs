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

use crate::arch::x86_64::acpi::tables::madt::*;
use crate::arch::x86_64::acpi::tables::SIG_MADT;
use crate::arch::x86_64::acpi::data::*;
use super::state::TableRegistry;

pub fn parse_madt(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_MADT) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let madt = ptr::read_volatile(addr as *const Madt);

        registry.data.lapic_address = madt.local_apic_address as u64;
        registry.data.has_legacy_pics = madt.has_legacy_pics();

        let madt_end = addr + madt.header.length as u64;
        let mut entry_ptr = addr + mem::size_of::<Madt>() as u64;

        while entry_ptr + 2 <= madt_end {
            let header = ptr::read_volatile(entry_ptr as *const MadtEntryHeader);

            if header.length < 2 || entry_ptr + header.length as u64 > madt_end {
                break;
            }

            match header.entry_type {
                0 => parse_local_apic(registry, entry_ptr, header.length),
                1 => parse_ioapic(registry, entry_ptr, header.length),
                2 => parse_interrupt_override(registry, entry_ptr, header.length),
                4 => parse_local_apic_nmi(registry, entry_ptr, header.length),
                5 => parse_lapic_override(registry, entry_ptr, header.length),
                9 => parse_x2apic(registry, entry_ptr, header.length),
                10 => parse_x2apic_nmi(registry, entry_ptr, header.length),
                _ => {}
            }

            entry_ptr += header.length as u64;
        }
    }
}

fn parse_local_apic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApic>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApic);
        if entry.is_usable() {
            registry.data.processors.push(ProcessorInfo::new(
                entry.apic_id as u32, entry.processor_id as u32, false, entry.is_enabled(),
            ));
        }
    }
}

fn parse_ioapic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtIoApic>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtIoApic);
        registry.data.ioapics.push(IoApicInfo {
            id: entry.ioapic_id, address: entry.address as u64, gsi_base: entry.gsi_base,
        });
    }
}

fn parse_interrupt_override(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtInterruptOverride>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtInterruptOverride);
        registry.data.overrides.push(InterruptOverride {
            source_irq: entry.source, gsi: entry.gsi,
            polarity: entry.polarity(), trigger_mode: entry.trigger_mode(),
        });
    }
}

fn parse_local_apic_nmi(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApicNmi>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApicNmi);
        registry.data.nmis.push(NmiConfig {
            processor_uid: if entry.processor_id == 0xFF { u32::MAX } else { entry.processor_id as u32 },
            lint: entry.lint, flags: entry.flags,
        });
    }
}

fn parse_lapic_override(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApicOverride>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApicOverride);
        registry.data.lapic_address = entry.address;
    }
}

fn parse_x2apic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalX2Apic>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalX2Apic);
        if entry.is_usable() {
            registry.data.processors.push(ProcessorInfo::new(
                entry.x2apic_id, entry.processor_uid, true, entry.is_enabled(),
            ));
        }
    }
}

fn parse_x2apic_nmi(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalX2ApicNmi>() as u8 { return; }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalX2ApicNmi);
        registry.data.nmis.push(NmiConfig {
            processor_uid: entry.processor_uid, lint: entry.lint, flags: entry.flags,
        });
    }
}
