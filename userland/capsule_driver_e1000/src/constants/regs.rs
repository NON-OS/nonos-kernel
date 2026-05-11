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

//! Intel 8254x MMIO register offsets in BAR0. Register names match
//! the 82540EM / 82545EM software developer's manual. Only the
//! offsets the live driver actually touches are listed; manual-
//! mode EEPROM access (`EECD`), interrupt throttling (`ITR`),
//! interrupt cause set (`ICS`), and interrupt mask set (`IMS`)
//! belong to follow-on slices and are not declared here yet.

pub const REG_CTRL: usize = 0x0000;
pub const REG_STATUS: usize = 0x0008;
pub const REG_EERD: usize = 0x0014;

pub const REG_ICR: usize = 0x00C0;
pub const REG_IMC: usize = 0x00D8;

pub const REG_RCTL: usize = 0x0100;
pub const REG_TCTL: usize = 0x0400;
pub const REG_TIPG: usize = 0x0410;

pub const REG_RDBAL: usize = 0x2800;
pub const REG_RDBAH: usize = 0x2804;
pub const REG_RDLEN: usize = 0x2808;
pub const REG_RDH: usize = 0x2810;
pub const REG_RDT: usize = 0x2818;

pub const REG_TDBAL: usize = 0x3800;
pub const REG_TDBAH: usize = 0x3804;
pub const REG_TDLEN: usize = 0x3808;
pub const REG_TDH: usize = 0x3810;
pub const REG_TDT: usize = 0x3818;

pub const REG_MTA_BASE: usize = 0x5200;
pub const MTA_ENTRY_COUNT: usize = 128;

pub const REG_RAL0: usize = 0x5400;
pub const REG_RAH0: usize = 0x5404;
