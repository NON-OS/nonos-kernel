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
use crate::arch::x86_64::acpi::data::*;
use crate::arch::x86_64::acpi::tables::madt::*;

pub fn parse_local_apic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApic>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApic);
        if entry.is_usable() {
            registry.data.processors.push(ProcessorInfo::new(
                entry.apic_id as u32,
                entry.processor_id as u32,
                false,
                entry.is_enabled(),
            ));
        }
    }
}

pub fn parse_ioapic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtIoApic>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtIoApic);
        registry.data.ioapics.push(IoApicInfo {
            id: entry.ioapic_id,
            address: entry.address as u64,
            gsi_base: entry.gsi_base,
        });
    }
}

pub fn parse_interrupt_override(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtInterruptOverride>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtInterruptOverride);
        registry.data.overrides.push(InterruptOverride {
            source_irq: entry.source,
            gsi: entry.gsi,
            polarity: entry.polarity(),
            trigger_mode: entry.trigger_mode(),
        });
    }
}

pub fn parse_local_apic_nmi(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApicNmi>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApicNmi);
        registry.data.nmis.push(NmiConfig {
            processor_uid: if entry.processor_id == 0xFF {
                u32::MAX
            } else {
                entry.processor_id as u32
            },
            lint: entry.lint,
            flags: entry.flags,
        });
    }
}
