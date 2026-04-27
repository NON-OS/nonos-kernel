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

use super::super::super::error::WifiError;
use super::super::constants::MIC_LEN;
use super::super::crypto::{aes_key_unwrap, compute_mic_aes_cmac};
use super::types::WpaContext;
use alloc::vec::Vec;

impl WpaContext {
    pub(super) fn verify_mic(
        &self,
        kck: &[u8],
        frame_data: &[u8],
        received_mic: &[u8],
    ) -> Result<bool, WifiError> {
        if received_mic.len() != MIC_LEN {
            return Ok(false);
        }
        if frame_data.len() < 99 {
            return Ok(false);
        }

        let mut frame_copy = Vec::from(frame_data);

        const MIC_OFFSET: usize = 81;
        for i in 0..MIC_LEN {
            if MIC_OFFSET + i < frame_copy.len() {
                frame_copy[MIC_OFFSET + i] = 0;
            }
        }

        let computed_mic = compute_mic_aes_cmac(kck, &frame_copy[4..])?;

        let mut diff = 0u8;
        for i in 0..MIC_LEN {
            diff |= computed_mic[i] ^ received_mic[i];
        }

        Ok(diff == 0)
    }

    pub(super) fn decrypt_key_data(
        &self,
        kek: &[u8],
        encrypted: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        if encrypted.len() < 24 || encrypted.len() % 8 != 0 {
            return Err(WifiError::InvalidFrame);
        }

        aes_key_unwrap(kek, encrypted)
    }
}
