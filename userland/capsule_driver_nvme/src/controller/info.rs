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

use crate::constants::{
    cap_dstrd, cap_mpsmax_shift, cap_mpsmin_shift, cap_mqes, cap_nvm_supported, cap_to, CSTS_CFS,
    CSTS_RDY, REG_AQA, REG_CAP, REG_CC, REG_CMBLOC, REG_CMBSZ, REG_CSTS, REG_INTMC, REG_INTMS,
    REG_VS,
};
use crate::regs::Regs;

#[derive(Debug, Clone, Copy)]
pub struct ControllerInfo {
    pub cap: u64,
    pub version: u32,
    pub cc: u32,
    pub csts: u32,
    pub aqa: u32,
    pub intms: u32,
    pub intmc: u32,
    pub cmbloc: u32,
    pub cmbsz: u32,
}

impl ControllerInfo {
    pub fn read(regs: Regs) -> Self {
        Self {
            cap: unsafe { regs.r64(REG_CAP) },
            version: unsafe { regs.r32(REG_VS) },
            cc: unsafe { regs.r32(REG_CC) },
            csts: unsafe { regs.r32(REG_CSTS) },
            aqa: unsafe { regs.r32(REG_AQA) },
            intms: unsafe { regs.r32(REG_INTMS) },
            intmc: unsafe { regs.r32(REG_INTMC) },
            cmbloc: unsafe { regs.r32(REG_CMBLOC) },
            cmbsz: unsafe { regs.r32(REG_CMBSZ) },
        }
    }

    pub fn is_nvme_register_block(self) -> bool {
        self.cap != 0 && self.version != 0 && cap_mqes(self.cap) != 0
    }

    pub const fn max_queue_entries(self) -> u16 {
        cap_mqes(self.cap)
    }

    pub const fn timeout_units(self) -> u8 {
        cap_to(self.cap)
    }

    pub const fn doorbell_stride(self) -> u8 {
        cap_dstrd(self.cap)
    }

    pub const fn min_page_shift(self) -> u8 {
        cap_mpsmin_shift(self.cap)
    }

    pub const fn max_page_shift(self) -> u8 {
        cap_mpsmax_shift(self.cap)
    }

    pub const fn nvm_supported(self) -> bool {
        cap_nvm_supported(self.cap)
    }

    pub const fn ready(self) -> bool {
        (self.csts & CSTS_RDY) != 0
    }

    pub const fn fatal(self) -> bool {
        (self.csts & CSTS_CFS) != 0
    }
}
