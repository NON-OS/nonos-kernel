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

pub const BOOT_SIGNATURE: u16 = 0xAA55;

pub const FSINFO_SIG1: u32 = 0x41615252;
pub const FSINFO_SIG2: u32 = 0x61417272;
pub const FSINFO_SIG3: u32 = 0xAA550000;

pub const FAT32_EOC: u32 = 0x0FFFFFF8;
pub const FAT32_BAD: u32 = 0x0FFFFFF7;
pub const FAT32_FREE: u32 = 0x00000000;
pub const FAT32_MASK: u32 = 0x0FFFFFFF;

pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_LONG_NAME: u8 = 0x0F;

pub const DIR_ENTRY_SIZE: usize = 32;
pub const DIR_ENTRY_FREE: u8 = 0xE5;
pub const DIR_ENTRY_END: u8 = 0x00;
