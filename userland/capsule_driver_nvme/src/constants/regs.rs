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

pub const REG_CAP: u32 = 0x0000;
pub const REG_VS: u32 = 0x0008;
pub const REG_INTMS: u32 = 0x000c;
pub const REG_INTMC: u32 = 0x0010;
pub const REG_CC: u32 = 0x0014;
pub const REG_CSTS: u32 = 0x001c;
pub const REG_AQA: u32 = 0x0024;
pub const REG_ASQ: u32 = 0x0028;
pub const REG_ACQ: u32 = 0x0030;
pub const REG_CMBLOC: u32 = 0x0038;
pub const REG_CMBSZ: u32 = 0x003c;
pub const REG_DOORBELL_BASE: u32 = 0x1000;

pub const CC_EN: u32 = 1 << 0;
pub const CC_IOSQES_64: u32 = 6 << 16;
pub const CC_IOCQES_16: u32 = 4 << 20;
pub const CSTS_RDY: u32 = 1 << 0;
pub const CSTS_CFS: u32 = 1 << 1;
