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

use core::sync::atomic::Ordering;

use super::super::constants::*;
use super::super::error::{response_codes, TpmError, TpmResult};
use super::super::mmio::mmio_read32;
use super::core::TpmDriver;

impl TpmDriver {
    pub(crate) fn init(&mut self) -> TpmResult<()> {
        if !self.probe() {
            return Err(TpmError::NotPresent);
        }

        self.request_locality(0)?;

        unsafe {
            self.manufacturer = mmio_read32(self.base + regs::TPM_DID_VID);
            self.version = mmio_read32(self.base + regs::TPM_RID);
        }

        self.startup(false)?;

        self.self_test(true)?;

        self.initialized.store(true, Ordering::SeqCst);

        crate::log_info!(
            "[TPM] TPM 2.0 initialized: manufacturer=0x{:08X} version=0x{:08X}",
            self.manufacturer,
            self.version
        );

        Ok(())
    }

    pub(crate) fn startup(&self, resume: bool) -> TpmResult<()> {
        let mut cmd = [0u8; 12];

        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_STARTUP.to_be_bytes());

        let su_type = if resume {
            startup::TPM2_SU_STATE
        } else {
            startup::TPM2_SU_CLEAR
        };
        cmd[10..12].copy_from_slice(&su_type.to_be_bytes());

        let mut response = [0u8; 10];
        self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 && rc != response_codes::TPM_RC_INITIALIZE {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }

    pub(crate) fn self_test(&self, full: bool) -> TpmResult<()> {
        let mut cmd = [0u8; 11];

        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&11u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_SELF_TEST.to_be_bytes());
        cmd[10] = if full { 1 } else { 0 };

        let mut response = [0u8; 10];
        self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }
}
