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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::super::constants::*;
use super::super::error::{_parse_response_code, _ResponseCodeInfo, TpmError, TpmResult};
use super::super::status::PcrBankConfig;
use super::core::TpmDriver;
use crate::drivers::security::rate_limiter::DriverOpType;

impl TpmDriver {
    pub(crate) fn get_random(&self, count: u16) -> TpmResult<Vec<u8>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if self.random_rate_limiter.check_rate(DriverOpType::ControlOp).is_err() {
            return Err(TpmError::RateLimitExceeded);
        }

        if count > TPM_MAX_RANDOM_BYTES {
            return Err(TpmError::InvalidParameter);
        }

        let mut cmd = [0u8; 12];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_GET_RANDOM.to_be_bytes());
        cmd[10..12].copy_from_slice(&count.to_be_bytes());

        let mut response = [0u8; 128];
        let resp_size = self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        if resp_size < 12 {
            return Err(TpmError::InvalidResponse);
        }

        let random_size = u16::from_be_bytes([response[10], response[11]]) as usize;
        if resp_size < 12 + random_size {
            return Err(TpmError::InvalidResponse);
        }

        Ok(response[12..12 + random_size].to_vec())
    }

    pub(crate) fn shutdown(&self, state_save: bool) -> TpmResult<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        let mut cmd = [0u8; 12];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_SHUTDOWN.to_be_bytes());

        let su_type = if state_save {
            startup::TPM2_SU_STATE
        } else {
            startup::TPM2_SU_CLEAR
        };
        cmd[10..12].copy_from_slice(&su_type.to_be_bytes());

        let mut response = [0u8; 10];
        self.execute_command(&cmd, &mut response)?;

        Ok(())
    }

    pub(crate) fn create_quote(&self, pcr_selection: &[u32], nonce: &[u8]) -> TpmResult<Vec<u8>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if pcr_selection.is_empty() || pcr_selection.len() > TPM_NUM_PCRS {
            return Err(TpmError::InvalidParameter);
        }

        if nonce.len() > TPM_MAX_DIGEST_SIZE {
            return Err(TpmError::InvalidParameter);
        }

        let cmd_size: u32 = 10 + 4 + 4 + 9 + 2 + (nonce.len() as u32) + 2 + 10;

        let mut cmd = Vec::with_capacity(cmd_size as usize);

        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&cmd_size.to_be_bytes());
        cmd.extend_from_slice(&commands::TPM2_CC_QUOTE.to_be_bytes());

        cmd.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());

        let auth_size = 9u32;
        cmd.extend_from_slice(&auth_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes());
        cmd.push(0);
        cmd.extend_from_slice(&0u16.to_be_bytes());

        cmd.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        cmd.extend_from_slice(nonce);

        cmd.extend_from_slice(&alg::TPM2_ALG_NULL.to_be_bytes());

        cmd.extend_from_slice(&1u32.to_be_bytes());
        cmd.extend_from_slice(&alg::TPM2_ALG_SHA256.to_be_bytes());
        cmd.push(3);

        let mut pcr_bitmap = [0u8; 3];
        for &pcr in pcr_selection {
            if pcr < TPM_NUM_PCRS as u32 {
                let byte_idx = (pcr / 8) as usize;
                let bit_idx = (pcr % 8) as u8;
                pcr_bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
        cmd.extend_from_slice(&pcr_bitmap);

        debug_assert_eq!(cmd.len(), cmd_size as usize, "Quote command size mismatch");

        let mut response = [0u8; 1024];
        let resp_size = self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            crate::log_warn!("[TPM] Quote failed with code 0x{:08x}", rc);
            return Err(TpmError::CommandFailed(rc));
        }

        if resp_size < 14 {
            return Err(TpmError::InvalidResponse);
        }

        Ok(response[10..resp_size].to_vec())
    }

    pub(crate) fn _get_buffer_copy(&self) -> [u8; TPM_BUFFER_SIZE] {
        *self._buffer.lock()
    }

    pub(crate) fn _get_pcr_banks(&self) -> PcrBankConfig {
        self._pcr_banks.lock().clone()
    }

    pub(crate) fn _set_pcr_banks(&self, config: PcrBankConfig) {
        *self._pcr_banks.lock() = config;
    }

    pub(crate) fn _parse_last_error(response_code: u32) -> _ResponseCodeInfo {
        _parse_response_code(response_code)
    }
}
