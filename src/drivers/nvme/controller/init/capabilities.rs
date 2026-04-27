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

use super::super::super::constants::{REG_CAP, REG_VS};
use super::super::super::error::NvmeError;
use super::super::super::types::ControllerCapabilities;
use crate::memory::mmio::{mmio_r32, mmio_r64};
use x86_64::VirtAddr;

pub fn read_capabilities(mmio_base: usize) -> Result<ControllerCapabilities, NvmeError> {
    let cap = mmio_r64(VirtAddr::new((mmio_base + REG_CAP) as u64));
    Ok(ControllerCapabilities::from_register(cap))
}

pub fn read_version(mmio_base: usize) -> u32 {
    mmio_r32(VirtAddr::new((mmio_base + REG_VS) as u64))
}
