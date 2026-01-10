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

pub const KERNEL_PHYS_END: u64 = 0x0000_0000_4000_0000;
pub const MAX_DMA_SIZE: usize = 128 * 1024 * 1024;
pub const PAGE_SIZE: usize = 4096;
pub const MAX_PRP_ENTRIES: usize = 512;
pub const MAX_PHYS_ADDR_BITS: u8 = 52;
pub const PCI_MAX_BUS: u8 = 255;
pub const PCI_MAX_DEVICE: u8 = 31;
pub const PCI_MAX_FUNCTION: u8 = 7;
pub const PCI_CONFIG_SPACE_SIZE: u16 = 256;
pub const PCI_EXTENDED_CONFIG_SIZE: u16 = 4096;
pub const PROTECTED_CONFIG_OFFSETS: &[u8] = &[0x04, 0x0C, 0x0D, 0x3C, 0x3D];
pub const LOW_MMIO_START: usize = 0xE000_0000;
pub const LOW_MMIO_END: usize = 0xFFFF_FFFF;
pub const PLATFORM_MMIO_START: usize = 0xFED0_0000;
pub const PLATFORM_MMIO_END: usize = 0xFEE0_0000;
pub const HIGH_MMIO_START: usize = 0x1_0000_0000;
pub const DEFAULT_IO_OPS_PER_SEC: u32 = 100_000;
pub const DEFAULT_ADMIN_OPS_PER_SEC: u32 = 1_000;
pub const DEFAULT_DMA_OPS_PER_SEC: u32 = 10_000;
pub const RATE_LIMIT_WINDOW_MS: u64 = 1000;
pub const ASSUMED_CPU_FREQ_MHZ: u64 = 3000;
