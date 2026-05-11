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

//! PCI identifiers for Intel 8254x-class NICs. `0x100E` is the
//! 82540EM that QEMU emulates with `-device e1000`; the others are
//! family members the same register layout drives. The discovery
//! step accepts any of them; physical-hardware-only IDs (8259x,
//! e1000e family) live in their own slice.

pub const INTEL_VENDOR_ID: u16 = 0x8086;

pub const E1000_82540EM: u16 = 0x100E;
pub const E1000_82545EM_C: u16 = 0x100F;
pub const E1000_82545EM_F: u16 = 0x1011;
pub const E1000_82546EB_C: u16 = 0x1010;
pub const E1000_82547EI: u16 = 0x1019;

pub const E1000_DEVICE_IDS: &[u16] = &[
    E1000_82540EM,
    E1000_82545EM_C,
    E1000_82545EM_F,
    E1000_82546EB_C,
    E1000_82547EI,
];

// MMIO register window lives in BAR0; flash + I/O BARs are not
// touched by this capsule. The window length comes from the
// broker device record at discovery time, so we do not pin it
// here.
pub const BAR_INDEX: u32 = 0;
pub const BAR_OFFSET: u64 = 0;
