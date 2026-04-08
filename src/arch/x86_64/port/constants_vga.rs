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

pub const VGA_MISC_WRITE: u16 = 0x3C2;
pub const VGA_MISC_READ: u16 = 0x3CC;
pub const VGA_SEQ_INDEX: u16 = 0x3C4;
pub const VGA_SEQ_DATA: u16 = 0x3C5;
pub const VGA_GC_INDEX: u16 = 0x3CE;
pub const VGA_GC_DATA: u16 = 0x3CF;
pub const VGA_CRTC_INDEX: u16 = 0x3D4;
pub const VGA_CRTC_DATA: u16 = 0x3D5;
pub const VGA_AC_INDEX: u16 = 0x3C0;
pub const VGA_AC_WRITE: u16 = 0x3C0;
pub const VGA_AC_READ: u16 = 0x3C1;
pub const VGA_DAC_READ_INDEX: u16 = 0x3C7;
pub const VGA_DAC_WRITE_INDEX: u16 = 0x3C8;
pub const VGA_DAC_DATA: u16 = 0x3C9;
pub const VGA_INPUT_STATUS_1: u16 = 0x3DA;

pub const FDC2_STATUS_A: u16 = 0x370;
pub const FDC2_STATUS_B: u16 = 0x371;
pub const FDC2_DOR: u16 = 0x372;
pub const FDC2_TDR: u16 = 0x373;
pub const FDC2_MSR: u16 = 0x374;
pub const FDC2_DSR: u16 = 0x374;
pub const FDC2_FIFO: u16 = 0x375;
pub const FDC2_DIR: u16 = 0x377;
pub const FDC2_CCR: u16 = 0x377;

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub const ACPI_PM1A_EVT_BLK: u16 = 0x600;
pub const ACPI_PM1A_CNT_BLK: u16 = 0x604;
pub const ACPI_PM_TMR_BLK: u16 = 0x608;
pub const ACPI_GPE0_BLK: u16 = 0x620;
