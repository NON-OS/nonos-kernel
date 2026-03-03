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

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub const PCI_MAX_BUS: u8 = 255;
pub const PCI_MAX_DEVICE: u8 = 31;
pub const PCI_MAX_FUNCTION: u8 = 7;
pub const PCI_CONFIG_SPACE_SIZE: u16 = 256;
pub const PCIE_CONFIG_SPACE_SIZE: u16 = 4096;

pub const CFG_VENDOR_ID: u16 = 0x00;
pub const CFG_DEVICE_ID: u16 = 0x02;
pub const CFG_COMMAND: u16 = 0x04;
pub const CFG_STATUS: u16 = 0x06;
pub const CFG_REVISION_ID: u16 = 0x08;
pub const CFG_PROG_IF: u16 = 0x09;
pub const CFG_SUBCLASS: u16 = 0x0A;
pub const CFG_CLASS_CODE: u16 = 0x0B;
pub const CFG_CACHE_LINE_SIZE: u16 = 0x0C;
pub const CFG_LATENCY_TIMER: u16 = 0x0D;
pub const CFG_HEADER_TYPE: u16 = 0x0E;
pub const CFG_BIST: u16 = 0x0F;
pub const CFG_BAR0: u16 = 0x10;
pub const CFG_BAR1: u16 = 0x14;
pub const CFG_BAR2: u16 = 0x18;
pub const CFG_BAR3: u16 = 0x1C;
pub const CFG_BAR4: u16 = 0x20;
pub const CFG_BAR5: u16 = 0x24;
pub const CFG_CARDBUS_CIS: u16 = 0x28;
pub const CFG_SUBSYSTEM_VENDOR_ID: u16 = 0x2C;
pub const CFG_SUBSYSTEM_ID: u16 = 0x2E;
pub const CFG_EXPANSION_ROM_BASE: u16 = 0x30;
pub const CFG_CAPABILITIES_PTR: u16 = 0x34;
pub const CFG_INTERRUPT_LINE: u16 = 0x3C;
pub const CFG_INTERRUPT_PIN: u16 = 0x3D;
pub const CFG_MIN_GRANT: u16 = 0x3E;
pub const CFG_MAX_LATENCY: u16 = 0x3F;

pub const CFG_PRIMARY_BUS: u16 = 0x18;
pub const CFG_SECONDARY_BUS: u16 = 0x19;
pub const CFG_SUBORDINATE_BUS: u16 = 0x1A;
pub const CFG_SECONDARY_LATENCY: u16 = 0x1B;
pub const CFG_IO_BASE: u16 = 0x1C;
pub const CFG_IO_LIMIT: u16 = 0x1D;
pub const CFG_SECONDARY_STATUS: u16 = 0x1E;
pub const CFG_MEMORY_BASE: u16 = 0x20;
pub const CFG_MEMORY_LIMIT: u16 = 0x22;
pub const CFG_PREFETCH_MEMORY_BASE: u16 = 0x24;
pub const CFG_PREFETCH_MEMORY_LIMIT: u16 = 0x26;
pub const CFG_PREFETCH_BASE_UPPER: u16 = 0x28;
pub const CFG_PREFETCH_LIMIT_UPPER: u16 = 0x2C;
pub const CFG_IO_BASE_UPPER: u16 = 0x30;
pub const CFG_IO_LIMIT_UPPER: u16 = 0x32;
pub const CFG_BRIDGE_CONTROL: u16 = 0x3E;

pub const CMD_IO_SPACE: u16 = 1 << 0;
pub const CMD_MEMORY_SPACE: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;
pub const CMD_SPECIAL_CYCLES: u16 = 1 << 3;
pub const CMD_MWI_ENABLE: u16 = 1 << 4;
pub const CMD_VGA_PALETTE_SNOOP: u16 = 1 << 5;
pub const CMD_PARITY_ERROR_RESPONSE: u16 = 1 << 6;
pub const CMD_SERR_ENABLE: u16 = 1 << 8;
pub const CMD_FAST_B2B_ENABLE: u16 = 1 << 9;
pub const CMD_INTERRUPT_DISABLE: u16 = 1 << 10;

pub const STS_INTERRUPT_STATUS: u16 = 1 << 3;
pub const STS_CAPABILITIES_LIST: u16 = 1 << 4;
pub const STS_66MHZ_CAPABLE: u16 = 1 << 5;
pub const STS_FAST_B2B_CAPABLE: u16 = 1 << 7;
pub const STS_MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
pub const STS_DEVSEL_TIMING_MASK: u16 = 0x3 << 9;
pub const STS_SIGNALED_TARGET_ABORT: u16 = 1 << 11;
pub const STS_RECEIVED_TARGET_ABORT: u16 = 1 << 12;
pub const STS_RECEIVED_MASTER_ABORT: u16 = 1 << 13;
pub const STS_SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
pub const STS_DETECTED_PARITY_ERROR: u16 = 1 << 15;

pub const HDR_TYPE_STANDARD: u8 = 0x00;
pub const HDR_TYPE_BRIDGE: u8 = 0x01;
pub const HDR_TYPE_CARDBUS: u8 = 0x02;
pub const HDR_TYPE_MULTIFUNCTION: u8 = 0x80;

pub const BAR_TYPE_MASK: u32 = 0x01;
pub const BAR_TYPE_MEMORY: u32 = 0x00;
pub const BAR_TYPE_IO: u32 = 0x01;
pub const BAR_MEMORY_TYPE_MASK: u32 = 0x06;
pub const BAR_MEMORY_TYPE_32: u32 = 0x00;
pub const BAR_MEMORY_TYPE_64: u32 = 0x04;
pub const BAR_MEMORY_PREFETCHABLE: u32 = 0x08;
pub const BAR_MEMORY_ADDR_MASK: u32 = 0xFFFF_FFF0;
pub const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC;

pub const MAX_BAR_SIZE: u64 = 256 * 1024 * 1024 * 1024;
pub const MIN_MMIO_ADDRESS: u64 = 0x100000;
pub const MAX_PHYSICAL_ADDRESS: u64 = 0x0000_FFFF_FFFF_FFFF;
