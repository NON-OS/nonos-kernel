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

mod cap;
mod pci;
mod regs;

pub use cap::{cap_dstrd, cap_mpsmax_shift, cap_mpsmin_shift, cap_mqes, cap_nvm_supported, cap_to};
pub use pci::{CLASS_BLOCK, NVME_BAR_INDEX, NVME_BAR_MIN_SIZE};
pub use regs::{
    CC_EN, CC_IOCQES_16, CC_IOSQES_64, CSTS_CFS, CSTS_RDY, REG_ACQ, REG_AQA, REG_ASQ, REG_CAP,
    REG_CC, REG_CMBLOC, REG_CMBSZ, REG_CSTS, REG_DOORBELL_BASE, REG_INTMC, REG_INTMS, REG_VS,
};
