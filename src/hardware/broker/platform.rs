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

//! Synthetic platform/ACPI device entries. These are devices the
//! kernel knows about by convention rather than through PCI
//! enumeration: PS/2 controller, COM ports, RTC. Register them
//! once after `init_from_pci` so they show up in the same
//! `MkDeviceList` snapshot.

use super::class::ids;
use super::device::{Bar, BarKind, BusKind, DeviceRecord};
use super::table;

// PNP id of the IBM-compatible PS/2 keyboard controller. Carried
// in the `vendor`/`device` slots of the synthetic record so
// userland discovery has something stable to match on without a
// PCI table lookup.
pub const PNP_VENDOR_PS2_KBD: u16 = 0x0001;
pub const PNP_DEVICE_PS2_KBD: u16 = 0x0303;

const PS2_PORT_BASE: u64 = 0x60;
const PS2_PORT_COUNT: u64 = 5; // 0x60..=0x64 inclusive
const PS2_KBD_IRQ: u8 = 1;

/// Register the legacy platform devices known to the kernel.
/// Currently the i8042 PS/2 keyboard controller; mouse, COM
/// ports, and the RTC are deferred until their capsules land.
pub fn register_legacy() -> u64 {
    let mut bars = [Bar::empty(); 6];
    bars[0] = Bar {
        base: PS2_PORT_BASE,
        size: PS2_PORT_COUNT,
        kind: BarKind::Pio as u8,
        flags: 0,
        _pad: [0; 6],
    };
    let record = DeviceRecord {
        device_id: 0,
        bus_kind: BusKind::Acpi as u8,
        _pad0: [0; 3],
        class: ids::INPUT,
        vendor: PNP_VENDOR_PS2_KBD,
        device: PNP_DEVICE_PS2_KBD,
        flags: 0,
        bar_count: 1,
        irq_line: PS2_KBD_IRQ,
        irq_pin: 1,
        _pad1: [0; 5],
        bars,
    };
    table::register_platform_device(record)
}
