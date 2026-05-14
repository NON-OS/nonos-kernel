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

use crate::constants::{HBA_CAP, HBA_CAP2, HBA_GHC, HBA_PI, HBA_VS};
use crate::regs::Regs;

#[derive(Debug, Clone, Copy)]
pub struct ControllerInfo {
    pub cap: u32,
    pub ghc: u32,
    pub pi: u32,
    pub version: u32,
    pub cap2: u32,
    pub port_count: u8,
}

impl ControllerInfo {
    pub fn read(regs: Regs) -> Self {
        let cap = unsafe { regs.r32(HBA_CAP) };
        let port_count = ((cap & 0x1f) + 1) as u8;
        Self {
            cap,
            ghc: unsafe { regs.r32(HBA_GHC) },
            pi: unsafe { regs.r32(HBA_PI) },
            version: unsafe { regs.r32(HBA_VS) },
            cap2: unsafe { regs.r32(HBA_CAP2) },
            port_count,
        }
    }
}
