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

// Wire-form view of a device, returned by `MkDeviceList`. Layout is
// fixed; field order matches `abi/driver_broker_abi.md`. The struct
// is `repr(C)` and `Copy` so it can be written directly into a user
// buffer with usercopy.

pub const BUS_KIND_PCI: u8 = 1;
pub const BUS_KIND_ACPI: u8 = 2;
pub const BUS_KIND_VIRT: u8 = 3;

pub const BAR_KIND_NONE: u8 = 0;
pub const BAR_KIND_MMIO: u8 = 1;
pub const BAR_KIND_PIO: u8 = 2;

pub const BAR_FLAG_PREFETCH: u8 = 1 << 0;
pub const BAR_FLAG_MEM64: u8 = 1 << 1;

pub const DEVICE_FLAG_CLAIMED: u32 = 1 << 0;
pub const DEVICE_FLAG_DISABLED: u32 = 1 << 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    Pci = BUS_KIND_PCI,
    Acpi = BUS_KIND_ACPI,
    Virt = BUS_KIND_VIRT,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarKind {
    None = BAR_KIND_NONE,
    Mmio = BAR_KIND_MMIO,
    Pio = BAR_KIND_PIO,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Bar {
    pub base: u64,
    pub size: u64,
    pub kind: u8,
    pub flags: u8,
    pub _pad: [u8; 6],
}

impl Bar {
    pub const fn empty() -> Self {
        Self { base: 0, size: 0, kind: BAR_KIND_NONE, flags: 0, _pad: [0; 6] }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeviceRecord {
    pub device_id: u64,
    pub bus_kind: u8,
    pub _pad0: [u8; 3],
    pub class: u32,
    pub vendor: u16,
    pub device: u16,
    pub flags: u32,
    pub bar_count: u8,
    pub _pad1: [u8; 7],
    pub bars: [Bar; 6],
}

impl DeviceRecord {
    pub const fn empty() -> Self {
        Self {
            device_id: 0,
            bus_kind: 0,
            _pad0: [0; 3],
            class: 0,
            vendor: 0,
            device: 0,
            flags: 0,
            bar_count: 0,
            _pad1: [0; 7],
            bars: [Bar::empty(); 6],
        }
    }
}

// Compile-time guarantee that the wire layout is what
// `driver_broker_abi.md` promises.
const _: () = {
    assert!(core::mem::size_of::<Bar>() == 24);
    assert!(core::mem::size_of::<DeviceRecord>() == 176);
};
