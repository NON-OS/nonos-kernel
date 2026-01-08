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

pub const VENDOR_QEMU: u16 = 0x1234;
pub const DEVICE_STD_VGA: u16 = 0x1111;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const VBE_INDEX_PORT: u16 = 0x1CE;
pub const VBE_DATA_PORT: u16 = 0x1CF;
pub const VBE_DISPI_INDEX_ID: u16 = 0x0;
pub const VBE_DISPI_INDEX_XRES: u16 = 0x1;
pub const VBE_DISPI_INDEX_YRES: u16 = 0x2;
pub const VBE_DISPI_INDEX_BPP: u16 = 0x3;
pub const VBE_DISPI_INDEX_ENABLE: u16 = 0x4;
pub const VBE_DISPI_INDEX_BANK: u16 = 0x5;
pub const VBE_DISPI_INDEX_VIRT_WIDTH: u16 = 0x6;
pub const VBE_DISPI_INDEX_VIRT_HEIGHT: u16 = 0x7;
pub const VBE_DISPI_INDEX_X_OFFSET: u16 = 0x8;
pub const VBE_DISPI_INDEX_Y_OFFSET: u16 = 0x9;
pub const VBE_DISPI_ENABLED: u16 = 0x01;
pub const VBE_DISPI_LFB_ENABLED: u16 = 0x40;
pub const VBE_DISPI_NOCLEARMEM: u16 = 0x80;
pub const VBE_DISPI_ID_MAGIC: u16 = 0xB0C5;
pub const DEFAULT_WIDTH: u16 = 1024;
pub const DEFAULT_HEIGHT: u16 = 768;
pub const DEFAULT_BPP: u16 = 32;
pub const PCI_COMMAND_OFFSET: u8 = 0x04;
pub const PCI_CMD_IO_ENABLE: u16 = 1 << 0;
pub const PCI_CMD_MEM_ENABLE: u16 = 1 << 1;
pub const PCI_CMD_BUS_MASTER: u16 = 1 << 2;
pub const SUPPORTED_MODES: &[(u16, u16)] = &[
    (640, 480),
    (800, 600),
    (1024, 768),
    (1280, 720),
    (1280, 1024),
    (1920, 1080),
];
pub const MIN_WIDTH: u16 = 320;
pub const MIN_HEIGHT: u16 = 200;
pub const MAX_WIDTH: u16 = 4096;
pub const MAX_HEIGHT: u16 = 3072;
