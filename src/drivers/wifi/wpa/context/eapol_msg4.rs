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
use super::super::constants::*;
use super::super::crypto::compute_mic_aes_cmac;
use super::types::WpaContext;
use alloc::vec::Vec;

impl WpaContext {
    pub(super) fn build_eapol_msg4(&self) -> Result<Vec<u8>, WifiError> {
        let mut frame = Vec::with_capacity(99);

        frame.push(0x02);
        frame.push(0x03);
        let body_len: u16 = 95;
        frame.extend_from_slice(&body_len.to_be_bytes());

        frame.push(EAPOL_KEY_TYPE_RSN);

        let key_info: u16 = 0x030A;
        frame.extend_from_slice(&key_info.to_be_bytes());

        frame.extend_from_slice(&16u16.to_be_bytes());

        frame.extend_from_slice(&self.replay_counter.to_be_bytes());

        frame.extend_from_slice(&[0u8; NONCE_LEN]);

        frame.extend_from_slice(&[0u8; 16 + 8 + 8]);

        let mic_offset = frame.len();
        frame.extend_from_slice(&[0u8; MIC_LEN]);

        frame.extend_from_slice(&0u16.to_be_bytes());

        let kck = &self.ptk[0..KCK_LEN];
        let mic = compute_mic_aes_cmac(kck, &frame[4..])?;
        frame[mic_offset..mic_offset + MIC_LEN].copy_from_slice(&mic);

        Ok(frame)
    }
}
