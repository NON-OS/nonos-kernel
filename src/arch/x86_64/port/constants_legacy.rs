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

pub const PIC1_COMMAND: u16 = 0x20;
pub const PIC1_DATA: u16 = 0x21;
pub const PIC2_COMMAND: u16 = 0xA0;
pub const PIC2_DATA: u16 = 0xA1;

pub const PIT_CHANNEL0: u16 = 0x40;
pub const PIT_CHANNEL1: u16 = 0x41;
pub const PIT_CHANNEL2: u16 = 0x42;
pub const PIT_COMMAND: u16 = 0x43;

pub const PS2_DATA: u16 = 0x60;
pub const PS2_STATUS: u16 = 0x64;
pub const PS2_COMMAND: u16 = 0x64;

pub const CMOS_ADDRESS: u16 = 0x70;
pub const CMOS_DATA: u16 = 0x71;
pub const NMI_STATUS: u16 = 0x61;

pub const FPU_CLEAR_BUSY: u16 = 0xF0;
pub const FPU_RESET: u16 = 0xF1;

pub const PC_SPEAKER: u16 = 0x61;

pub const QEMU_DEBUG: u16 = 0x402;
pub const BOCHS_DEBUG: u16 = 0xE9;
