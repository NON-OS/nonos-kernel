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

use super::super::constants::*;
use super::super::error::MmioResult;
use super::super::ops;
use super::api::MMIO_MANAGER;
use crate::memory::addr::VirtAddr;

pub unsafe fn read8(va: VirtAddr, offset: usize) -> MmioResult<u8> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_8)?;
        Ok(ops::read8_at(va.as_u64() + offset as u64))
    }
}
pub unsafe fn read16(va: VirtAddr, offset: usize) -> MmioResult<u16> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_16)?;
        Ok(ops::read16_at(va.as_u64() + offset as u64))
    }
}
pub unsafe fn read32(va: VirtAddr, offset: usize) -> MmioResult<u32> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_32)?;
        Ok(ops::read32_at(va.as_u64() + offset as u64))
    }
}
pub unsafe fn read64(va: VirtAddr, offset: usize) -> MmioResult<u64> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_64)?;
        Ok(ops::read64_at(va.as_u64() + offset as u64))
    }
}
pub unsafe fn write8(va: VirtAddr, offset: usize, value: u8) -> MmioResult<()> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_8)?;
        ops::write8_at(va.as_u64() + offset as u64, value);
        Ok(())
    }
}
pub unsafe fn write16(va: VirtAddr, offset: usize, value: u16) -> MmioResult<()> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_16)?;
        ops::write16_at(va.as_u64() + offset as u64, value);
        Ok(())
    }
}
pub unsafe fn write32(va: VirtAddr, offset: usize, value: u32) -> MmioResult<()> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_32)?;
        ops::write32_at(va.as_u64() + offset as u64, value);
        Ok(())
    }
}
pub unsafe fn write64(va: VirtAddr, offset: usize, value: u64) -> MmioResult<()> {
    unsafe {
        let m = MMIO_MANAGER.lock();
        m.validate_access(va, offset, ACCESS_SIZE_64)?;
        ops::write64_at(va.as_u64() + offset as u64, value);
        Ok(())
    }
}
