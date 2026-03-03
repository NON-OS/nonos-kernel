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
use super::super::error::{TpmError, TpmResult};
use super::core::TpmDriver;

impl TpmDriver {
    pub(crate) fn pcr_extend(&self, pcr_index: u32, hash_alg: u16, digest: &[u8]) -> TpmResult<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if pcr_index >= TPM_NUM_PCRS as u32 {
            return Err(TpmError::InvalidParameter);
        }

        let expected_digest_len = match hash_alg {
            alg::TPM2_ALG_SHA1 => 20,
            alg::TPM2_ALG_SHA256 => 32,
            alg::TPM2_ALG_SHA384 => 48,
            alg::TPM2_ALG_SHA512 => 64,
            _ => return Err(TpmError::InvalidParameter),
        };

        if digest.len() != expected_digest_len {
            return Err(TpmError::InvalidParameter);
        }

        let cmd_size: u32 = 10 + 4 + 4 + 9 + 4 + 2 + (expected_digest_len as u32);

        let mut cmd = Vec::with_capacity(cmd_size as usize);

        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&cmd_size.to_be_bytes());
        cmd.extend_from_slice(&commands::TPM2_CC_PCR_EXTEND.to_be_bytes());

        cmd.extend_from_slice(&pcr_index.to_be_bytes());

        let auth_size = 9u32;
        cmd.extend_from_slice(&auth_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes());
        cmd.push(0);
        cmd.extend_from_slice(&0u16.to_be_bytes());

        cmd.extend_from_slice(&1u32.to_be_bytes());

        cmd.extend_from_slice(&hash_alg.to_be_bytes());
        cmd.extend_from_slice(digest);

        debug_assert_eq!(cmd.len(), cmd_size as usize, "PCR_Extend command size mismatch");

        let mut response = [0u8; 64];
        self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }

    pub(crate) fn pcr_read(&self, pcr_index: u32, hash_alg: u16) -> TpmResult<Vec<u8>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if pcr_index >= TPM_NUM_PCRS as u32 {
            return Err(TpmError::InvalidParameter);
        }

        const CMD_SIZE: u32 = 10 + 10;

        let mut cmd = Vec::with_capacity(CMD_SIZE as usize);

        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&CMD_SIZE.to_be_bytes());
        cmd.extend_from_slice(&commands::TPM2_CC_PCR_READ.to_be_bytes());

        cmd.extend_from_slice(&1u32.to_be_bytes());
        cmd.extend_from_slice(&hash_alg.to_be_bytes());
        cmd.push(3);

        let byte_idx = (pcr_index / 8) as usize;
        let bit_idx = (pcr_index % 8) as u8;
        let mut pcr_select = [0u8; 3];
        pcr_select[byte_idx] = 1 << bit_idx;
        cmd.extend_from_slice(&pcr_select);

        debug_assert_eq!(cmd.len(), CMD_SIZE as usize, "PCR_Read command size mismatch");

        let mut response = [0u8; 256];
        let resp_size = self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        const HEADER_SIZE: usize = 10;
        const UPDATE_COUNTER_SIZE: usize = 4;
        const PCR_SELECTION_OUT_SIZE: usize = 10;
        const DIGEST_COUNT_SIZE: usize = 4;
        const DIGEST_SIZE_FIELD: usize = 2;

        let preamble = HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + DIGEST_COUNT_SIZE;

        if resp_size < preamble + DIGEST_SIZE_FIELD {
            return Err(TpmError::InvalidResponse);
        }

        let digest_count = u32::from_be_bytes([
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE],
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + 1],
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + 2],
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + 3],
        ]);

        if digest_count == 0 {
            return Err(TpmError::InvalidResponse);
        }

        let digest_size = u16::from_be_bytes([response[preamble], response[preamble + 1]]) as usize;

        if resp_size < preamble + DIGEST_SIZE_FIELD + digest_size {
            return Err(TpmError::InvalidResponse);
        }

        Ok(response[preamble + DIGEST_SIZE_FIELD..preamble + DIGEST_SIZE_FIELD + digest_size].to_vec())
    }
}
