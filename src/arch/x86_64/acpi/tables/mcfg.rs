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

use super::sdt::SdtHeader;
use core::mem;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Mcfg {
    pub header: SdtHeader,
    pub reserved: u64,
}

impl Mcfg {
    pub fn entry_count(&self) -> usize {
        let data_len = self.header.length as usize - mem::size_of::<Self>();
        data_len / mem::size_of::<McfgEntry>()
    }

    pub fn entries_offset(&self) -> usize {
        mem::size_of::<Self>()
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct McfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    pub reserved: u32,
}

impl McfgEntry {
    pub fn config_address(&self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        if device >= 32 || function >= 8 || offset >= 4096 {
            return None;
        }
        Some(
            self.base_address
                + ((bus as u64) << 20)
                + ((device as u64) << 15)
                + ((function as u64) << 12)
                + (offset as u64),
        )
    }

    pub fn bus_count(&self) -> u16 {
        (self.end_bus as u16) - (self.start_bus as u16) + 1
    }

    pub fn contains_bus(&self, bus: u8) -> bool {
        bus >= self.start_bus && bus <= self.end_bus
    }

    pub fn memory_size(&self) -> u64 {
        (self.bus_count() as u64) << 20
    }
}

pub mod config_offsets {
    pub const VENDOR_ID: u16 = 0x00;
    pub const DEVICE_ID: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    pub const REVISION_ID: u16 = 0x08;
    pub const PROG_IF: u16 = 0x09;
    pub const SUBCLASS: u16 = 0x0A;
    pub const CLASS_CODE: u16 = 0x0B;
    pub const CACHE_LINE_SIZE: u16 = 0x0C;
    pub const LATENCY_TIMER: u16 = 0x0D;
    pub const HEADER_TYPE: u16 = 0x0E;
    pub const BIST: u16 = 0x0F;
    pub const BAR0: u16 = 0x10;
    pub const BAR1: u16 = 0x14;
    pub const BAR2: u16 = 0x18;
    pub const BAR3: u16 = 0x1C;
    pub const BAR4: u16 = 0x20;
    pub const BAR5: u16 = 0x24;
    pub const CARDBUS_CIS_PTR: u16 = 0x28;
    pub const SUBSYSTEM_VENDOR_ID: u16 = 0x2C;
    pub const SUBSYSTEM_ID: u16 = 0x2E;
    pub const EXPANSION_ROM_BASE: u16 = 0x30;
    pub const CAP_PTR: u16 = 0x34;
    pub const INT_LINE: u16 = 0x3C;
    pub const INT_PIN: u16 = 0x3D;
    pub const MIN_GNT: u16 = 0x3E;
    pub const MAX_LAT: u16 = 0x3F;
}

pub mod bridge_offsets {
    pub const PRIMARY_BUS: u16 = 0x18;
    pub const SECONDARY_BUS: u16 = 0x19;
    pub const SUBORDINATE_BUS: u16 = 0x1A;
    pub const SECONDARY_LATENCY: u16 = 0x1B;
    pub const IO_BASE: u16 = 0x1C;
    pub const IO_LIMIT: u16 = 0x1D;
    pub const SECONDARY_STATUS: u16 = 0x1E;
    pub const MEMORY_BASE: u16 = 0x20;
    pub const MEMORY_LIMIT: u16 = 0x22;
    pub const PREFETCH_BASE: u16 = 0x24;
    pub const PREFETCH_LIMIT: u16 = 0x26;
    pub const PREFETCH_BASE_UPPER: u16 = 0x28;
    pub const PREFETCH_LIMIT_UPPER: u16 = 0x2C;
    pub const IO_BASE_UPPER: u16 = 0x30;
    pub const IO_LIMIT_UPPER: u16 = 0x32;
    pub const BRIDGE_CONTROL: u16 = 0x3E;
}

pub mod command_bits {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_B2B_ENABLE: u16 = 1 << 9;
    pub const INT_DISABLE: u16 = 1 << 10;
}

pub mod status_bits {
    pub const INT_STATUS: u16 = 1 << 3;
    pub const CAP_LIST: u16 = 1 << 4;
    pub const MHZ_66_CAPABLE: u16 = 1 << 5;
    pub const FAST_B2B_CAPABLE: u16 = 1 << 7;
    pub const MASTER_PARITY_ERROR: u16 = 1 << 8;
    pub const DEVSEL_MASK: u16 = 0x03 << 9;
    pub const SIG_TARGET_ABORT: u16 = 1 << 11;
    pub const RCV_TARGET_ABORT: u16 = 1 << 12;
    pub const RCV_MASTER_ABORT: u16 = 1 << 13;
    pub const SIG_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}

pub mod header_type {
    pub const TYPE_MASK: u8 = 0x7F;
    pub const MULTI_FUNCTION: u8 = 0x80;
    pub const STANDARD: u8 = 0x00;
    pub const PCI_BRIDGE: u8 = 0x01;
    pub const CARDBUS_BRIDGE: u8 = 0x02;
}

pub mod capability_ids {
    pub const PM: u8 = 0x01;
    pub const AGP: u8 = 0x02;
    pub const VPD: u8 = 0x03;
    pub const SLOT_ID: u8 = 0x04;
    pub const MSI: u8 = 0x05;
    pub const COMPACT_PCI_HOT_SWAP: u8 = 0x06;
    pub const PCIX: u8 = 0x07;
    pub const HYPER_TRANSPORT: u8 = 0x08;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const DEBUG_PORT: u8 = 0x0A;
    pub const COMPACT_PCI_RESOURCE: u8 = 0x0B;
    pub const HOT_PLUG: u8 = 0x0C;
    pub const BRIDGE_SUBSYSTEM_VENDOR: u8 = 0x0D;
    pub const AGP8X: u8 = 0x0E;
    pub const SECURE_DEVICE: u8 = 0x0F;
    pub const PCIE: u8 = 0x10;
    pub const MSIX: u8 = 0x11;
    pub const SATA: u8 = 0x12;
    pub const AF: u8 = 0x13;
}

pub mod class_codes {
    pub const UNCLASSIFIED: u8 = 0x00;
    pub const MASS_STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const SIMPLE_COMM: u8 = 0x07;
    pub const BASE_SYSTEM: u8 = 0x08;
    pub const INPUT: u8 = 0x09;
    pub const DOCKING_STATION: u8 = 0x0A;
    pub const PROCESSOR: u8 = 0x0B;
    pub const SERIAL_BUS: u8 = 0x0C;
    pub const WIRELESS: u8 = 0x0D;
    pub const INTELLIGENT_IO: u8 = 0x0E;
    pub const SATELLITE_COMM: u8 = 0x0F;
    pub const ENCRYPTION: u8 = 0x10;
    pub const SIGNAL_PROCESSING: u8 = 0x11;
    pub const PROCESSING_ACCELERATOR: u8 = 0x12;
    pub const NON_ESSENTIAL: u8 = 0x13;
    pub const CO_PROCESSOR: u8 = 0x40;
    pub const UNASSIGNED: u8 = 0xFF;
}

pub mod bar_bits {
    pub const IO_SPACE: u32 = 1 << 0;
    pub const TYPE_MASK: u32 = 0x06;
    pub const TYPE_32BIT: u32 = 0x00;
    pub const TYPE_64BIT: u32 = 0x04;
    pub const PREFETCHABLE: u32 = 1 << 3;
    pub const MEMORY_MASK: u32 = !0x0F;
    pub const IO_MASK: u32 = !0x03;
}
