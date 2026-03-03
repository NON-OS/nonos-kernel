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

pub const REG_CTRL: u32 = 0x0000;
pub const REG_ICR: u32 = 0x00C0;
pub const REG_IMC: u32 = 0x00D8;
pub const REG_RCTL: u32 = 0x0100;
pub const REG_TCTL: u32 = 0x0400;
pub const REG_RDBAL: u32 = 0x2800;
pub const REG_RDBAH: u32 = 0x2804;
pub const REG_RDLEN: u32 = 0x2808;
pub const REG_RDH: u32 = 0x2810;
pub const REG_RDT: u32 = 0x2818;
pub const REG_TDBAL: u32 = 0x3800;
pub const REG_TDBAH: u32 = 0x3804;
pub const REG_TDLEN: u32 = 0x3808;
pub const REG_TDH: u32 = 0x3810;
pub const REG_TDT: u32 = 0x3818;
pub const REG_RAL0: u32 = 0x5400;
pub const REG_RAH0: u32 = 0x5404;

pub const CTRL_SLU: u32 = 1 << 6;
pub const CTRL_RST: u32 = 1 << 26;

pub const RCTL_EN: u32 = 1 << 1;
pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_BSIZE_2048: u32 = 0 << 16;
pub const RCTL_SECRC: u32 = 1 << 26;

pub const TCTL_EN: u32 = 1 << 1;
pub const TCTL_PSP: u32 = 1 << 3;
pub const TCTL_CT_SHIFT: u32 = 4;
pub const TCTL_COLD_SHIFT: u32 = 12;

pub const DESC_DD: u8 = 1 << 0;

pub const DESC_CMD_EOP: u8 = 1 << 0;
pub const DESC_CMD_IFCS: u8 = 1 << 1;
pub const DESC_CMD_RS: u8 = 1 << 3;

pub const NUM_RX_DESC: usize = 32;
pub const NUM_TX_DESC: usize = 32;
pub const RX_BUFFER_SIZE: usize = 2048;
