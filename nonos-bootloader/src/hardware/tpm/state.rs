// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;
use super::types::TpmError;

pub struct TpmState {
    pub(crate) base: u64,
    pub(crate) initialized: bool,
    pub(crate) version: u8,
}

impl TpmState {
    pub const fn new() -> Self {
        Self {
            base: TPM_MMIO_BASE,
            initialized: false,
            version: 0,
        }
    }

    pub(crate) fn read_reg8(&self, offset: u32) -> u8 {
        let addr = (self.base + offset as u64) as *const u8;
        unsafe { core::ptr::read_volatile(addr) }
    }

    pub(crate) fn write_reg8(&self, offset: u32, value: u8) {
        let addr = (self.base + offset as u64) as *mut u8;
        unsafe { core::ptr::write_volatile(addr, value) }
    }

    pub(crate) fn read_reg32(&self, offset: u32) -> u32 {
        let addr = (self.base + offset as u64) as *const u32;
        unsafe { core::ptr::read_volatile(addr) }
    }

    pub fn detect(&mut self) -> Result<bool, TpmError> {
        let did_vid = self.read_reg32(TPM_DID_VID);
        if did_vid == 0 || did_vid == 0xFFFF_FFFF {
            return Ok(false);
        }

        let interface_id = self.read_reg32(TPM_INTERFACE_ID);
        self.version = if (interface_id & 0x0F) == 0x00 { 12 } else { 20 };

        self.initialized = true;
        Ok(true)
    }

    pub fn request_locality(&self) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.write_reg8(TPM_ACCESS, TPM_ACCESS_REQUEST);

        for _ in 0..1000 {
            let access = self.read_reg8(TPM_ACCESS);
            if (access & TPM_ACCESS_ACTIVE) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(TpmError::Timeout)
    }

    pub fn release_locality(&self) {
        if self.initialized {
            self.write_reg8(TPM_ACCESS, TPM_ACCESS_ACTIVE);
        }
    }

    pub(crate) fn wait_for_status(&self, mask: u8, expected: u8) -> Result<(), TpmError> {
        for _ in 0..10000 {
            let sts = self.read_reg8(TPM_STS);
            if (sts & mask) == expected {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(TpmError::Timeout)
    }
}
