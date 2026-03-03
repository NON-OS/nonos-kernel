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

pub const NVME_CLASS: u8 = 0x01;
pub const NVME_SUBCLASS: u8 = 0x08;
pub const NVME_PROGIF: u8 = 0x02;
pub const NVME_BAR_INDEX: u8 = 0;

pub const REG_CAP: usize = 0x0000;
pub const REG_VS: usize = 0x0008;
pub const REG_INTMS: usize = 0x000C;
pub const REG_INTMC: usize = 0x0010;
pub const REG_CC: usize = 0x0014;
pub const REG_CSTS: usize = 0x001C;
pub const REG_NSSR: usize = 0x0020;
pub const REG_AQA: usize = 0x0024;
pub const REG_ASQ: usize = 0x0028;
pub const REG_ACQ: usize = 0x0030;
pub const REG_CMBLOC: usize = 0x0038;
pub const REG_CMBSZ: usize = 0x003C;
pub const REG_BPINFO: usize = 0x0040;
pub const REG_BPRSEL: usize = 0x0044;
pub const REG_BPMBL: usize = 0x0048;
pub const REG_DBS: usize = 0x1000;

pub const CAP_MQES_MASK: u64 = 0xFFFF;
pub const CAP_CQR_BIT: u64 = 1 << 16;
pub const CAP_AMS_SHIFT: u32 = 17;
pub const CAP_AMS_MASK: u64 = 0x3 << 17;
pub const CAP_TO_SHIFT: u32 = 24;
pub const CAP_TO_MASK: u64 = 0xFF << 24;
pub const CAP_DSTRD_SHIFT: u32 = 32;
pub const CAP_DSTRD_MASK: u64 = 0xF << 32;
pub const CAP_NSSRS_BIT: u64 = 1 << 36;
pub const CAP_CSS_SHIFT: u32 = 37;
pub const CAP_CSS_MASK: u64 = 0xFF << 37;
pub const CAP_BPS_BIT: u64 = 1 << 45;
pub const CAP_MPSMIN_SHIFT: u32 = 48;
pub const CAP_MPSMIN_MASK: u64 = 0xF << 48;
pub const CAP_MPSMAX_SHIFT: u32 = 52;
pub const CAP_MPSMAX_MASK: u64 = 0xF << 52;
pub const CAP_PMRS_BIT: u64 = 1 << 56;
pub const CAP_CMBS_BIT: u64 = 1 << 57;

pub const CC_EN: u32 = 1 << 0;
pub const CC_CSS_SHIFT: u32 = 4;
pub const CC_CSS_NVM: u32 = 0 << 4;
pub const CC_CSS_ADMIN_ONLY: u32 = 7 << 4;
pub const CC_MPS_SHIFT: u32 = 7;
pub const CC_MPS_MASK: u32 = 0xF << 7;
pub const CC_AMS_SHIFT: u32 = 11;
pub const CC_AMS_RR: u32 = 0 << 11;
pub const CC_AMS_WRR: u32 = 1 << 11;
pub const CC_AMS_VS: u32 = 7 << 11;
pub const CC_SHN_SHIFT: u32 = 14;
pub const CC_SHN_NONE: u32 = 0 << 14;
pub const CC_SHN_NORMAL: u32 = 1 << 14;
pub const CC_SHN_ABRUPT: u32 = 2 << 14;
pub const CC_IOSQES_SHIFT: u32 = 16;
pub const CC_IOCQES_SHIFT: u32 = 20;

pub const CSTS_RDY: u32 = 1 << 0;
pub const CSTS_CFS: u32 = 1 << 1;
pub const CSTS_SHST_SHIFT: u32 = 2;
pub const CSTS_SHST_MASK: u32 = 0x3 << 2;
pub const CSTS_SHST_NORMAL: u32 = 0 << 2;
pub const CSTS_SHST_OCCURRING: u32 = 1 << 2;
pub const CSTS_SHST_COMPLETE: u32 = 2 << 2;
pub const CSTS_NSSRO: u32 = 1 << 4;
pub const CSTS_PP: u32 = 1 << 5;

pub const AQA_ASQS_SHIFT: u32 = 0;
pub const AQA_ACQS_SHIFT: u32 = 16;
