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

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::super::constants::*;
use super::super::error::{TpmError, TpmResult};
use super::super::mmio::{delay_ms, mmio_read8, mmio_read32, mmio_write8, mmio_write32, spin_delay};
use super::super::status::PcrBankConfig;
use crate::drivers::security::rate_limiter::{DriverOpType, RateLimiter};

pub(crate) struct TpmDriver {
    pub(crate) base: u64,
    pub(crate) locality: u8,
    pub(crate) initialized: AtomicBool,
    pub(crate) manufacturer: u32,
    pub(crate) version: u32,
    pub(crate) _buffer: Mutex<[u8; TPM_BUFFER_SIZE]>,
    pub(crate) _pcr_banks: Mutex<PcrBankConfig>,
    pub(crate) command_rate_limiter: RateLimiter,
    pub(crate) random_rate_limiter: RateLimiter,
}

impl TpmDriver {
    pub(crate) fn new() -> Self {
        Self {
            base: TPM_LOCALITY_0,
            locality: 0,
            initialized: AtomicBool::new(false),
            manufacturer: 0,
            version: 0,
            _buffer: Mutex::new([0u8; TPM_BUFFER_SIZE]),
            _pcr_banks: Mutex::new(PcrBankConfig::default()),
            command_rate_limiter: RateLimiter::new(TPM_MAX_COMMANDS_PER_SEC),
            random_rate_limiter: RateLimiter::new(TPM_MAX_RANDOM_REQUESTS_PER_SEC),
        }
    }

    pub(crate) fn probe(&self) -> bool {
        unsafe {
            let did_vid = mmio_read32(self.base + regs::TPM_DID_VID);

            if did_vid == 0xFFFF_FFFF || did_vid == 0 {
                return false;
            }

            let intf_id = mmio_read32(self.base + regs::TPM_INTERFACE_ID);

            let intf_type = intf_id & 0x0F;
            if intf_type > 1 {
                return false;
            }

            let status = mmio_read32(self.base + regs::TPM_STS);
            (status & sts::TPM_STS_FAMILY_TPM2) != 0
        }
    }

    pub(crate) fn request_locality(&mut self, locality: u8) -> TpmResult<()> {
        if locality > 4 {
            return Err(TpmError::InvalidParameter);
        }

        let locality_base = TPM_MMIO_BASE + (locality as u64 * 0x1000);

        unsafe {
            mmio_write8(
                locality_base + regs::TPM_ACCESS,
                access::TPM_ACCESS_REQUEST_USE,
            );

            for _ in 0..LOCALITY_REQUEST_TIMEOUT_MS {
                let access_reg = mmio_read8(locality_base + regs::TPM_ACCESS);

                if (access_reg & access::TPM_ACCESS_ACTIVE_LOCALITY) != 0 {
                    self.base = locality_base;
                    self.locality = locality;
                    return Ok(());
                }

                delay_ms(1);
            }
        }

        Err(TpmError::Timeout)
    }

    pub(crate) fn wait_for_command_ready(&self) -> TpmResult<()> {
        unsafe {
            for _ in 0..COMMAND_READY_TIMEOUT_MS {
                let status = mmio_read32(self.base + regs::TPM_STS);

                if (status & sts::TPM_STS_COMMAND_READY) != 0 {
                    return Ok(());
                }

                mmio_write32(self.base + regs::TPM_STS, sts::TPM_STS_COMMAND_READY);

                spin_delay(1000);
            }
        }
        Err(TpmError::Timeout)
    }

    pub(crate) fn get_burst_count(&self) -> u16 {
        unsafe {
            let status = mmio_read32(self.base + regs::TPM_STS);
            ((status >> 8) & 0xFFFF) as u16
        }
    }

    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub(crate) fn get_locality(&self) -> u8 {
        self.locality
    }

    pub(crate) fn get_manufacturer(&self) -> u32 {
        self.manufacturer
    }

    pub(crate) fn get_version(&self) -> u32 {
        self.version
    }
}

impl Default for TpmDriver {
    fn default() -> Self {
        Self::new()
    }
}
