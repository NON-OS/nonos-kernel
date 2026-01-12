// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

extern crate alloc;
use alloc::vec::Vec;
use super::serial::serial_print;

/// Initializes the interrupt subsystem including APIC, IOAPIC and timer.
/// # Safety {
/// Must be called after CPU structures (GDT, IDT) are initialized
/// Must be called exactly once during boot
/// Interrupts will be enabled at the end of this function
/// }
pub unsafe fn init_interrupts() -> Result<(), &'static str> {
    use crate::arch::x86_64::interrupt::nonos_ioapic::{IsoFlags, MadtIoApic, MadtIso, MadtNmi};
    crate::arch::x86_64::interrupt::apic::init();
    match crate::arch::x86_64::acpi::init() {
        Ok(()) => {}
        Err(e) => {
            serial_print(format_args!("[BOOT] ACPI init failed: {:?} - using fallback\n", e));
        }
    }

    if crate::arch::x86_64::acpi::is_initialized() {
        if let Some(madt) = crate::arch::x86_64::acpi::madt::parse_madt() {
            let ioapics: Vec<MadtIoApic> = madt
                .ioapics
                .iter()
                .map(|io| MadtIoApic {
                    phys_base: io.address,
                    gsi_base: io.gsi_base,
                })
                .collect();

            let isos: Vec<MadtIso> = madt
                .isos
                .iter()
                .map(|iso| MadtIso {
                    bus_irq: iso.source_irq,
                    gsi: iso.gsi,
                    flags: IsoFlags::from_polarity_trigger(iso.polarity, iso.trigger_mode),
                })
                .collect();

            let nmis: Vec<MadtNmi> = madt
                .nmis
                .iter()
                .map(|nmi| MadtNmi {
                    cpu: nmi.processor_uid,
                    lint: nmi.lint,
                    flags: IsoFlags::from_bits_truncate(nmi.flags),
                })
                .collect();

            if let Err(e) =
                crate::arch::x86_64::interrupt::nonos_ioapic::init(&ioapics, &isos, &nmis)
            {
                serial_print(format_args!("[BOOT] IOAPIC init failed: {}\n", e.as_str()));
            } else {
                serial_print(format_args!(
                    "[BOOT] IOAPIC initialized: {} chips, {} ISOs, {} NMIs\n",
                    ioapics.len(),
                    isos.len(),
                    nmis.len()
                ));
            }
        }
    }

    crate::arch::x86_64::time::timer::init();
    x86_64::instructions::interrupts::enable();
    Ok(())
}
