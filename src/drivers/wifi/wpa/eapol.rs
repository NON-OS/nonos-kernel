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

use alloc::vec::Vec;
use super::super::error::WifiError;
use super::constants::*;

pub struct EapolFrame {
    pub version: u8,
    pub descriptor_type: u8,
    pub key_info: u16,
    pub key_len: u16,
    pub replay_counter: u64,
    pub nonce: [u8; NONCE_LEN],
    pub key_iv: [u8; 16],
    pub key_rsc: [u8; 8],
    pub mic: [u8; MIC_LEN],
    pub key_data: Vec<u8>,
}

impl EapolFrame {
    pub fn is_msg1(&self) -> bool {
        let key_info = self.key_info;
        (key_info & KEY_INFO_ACK) != 0 &&
        (key_info & KEY_INFO_MIC) == 0 &&
        (key_info & KEY_INFO_ENCRYPTED) == 0
    }

    pub fn is_msg3(&self) -> bool {
        let key_info = self.key_info;
        (key_info & KEY_INFO_ACK) != 0 &&
        (key_info & KEY_INFO_MIC) != 0 &&
        (key_info & KEY_INFO_INSTALL) != 0
    }
}

pub fn parse_eapol_frame(frame: &[u8]) -> Result<EapolFrame, WifiError> {
    if frame.len() < 99 {
        return Err(WifiError::InvalidFrame);
    }

    let version = frame[0];
    let packet_type = frame[1];
    let _body_len = u16::from_be_bytes([frame[2], frame[3]]);

    if packet_type != 0x03 {
        return Err(WifiError::InvalidFrame);
    }

    let descriptor_type = frame[4];
    let key_info = u16::from_be_bytes([frame[5], frame[6]]);
    let key_len = u16::from_be_bytes([frame[7], frame[8]]);
    let replay_counter = u64::from_be_bytes([
        frame[9], frame[10], frame[11], frame[12],
        frame[13], frame[14], frame[15], frame[16],
    ]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&frame[17..17 + NONCE_LEN]);

    let mut key_iv = [0u8; 16];
    key_iv.copy_from_slice(&frame[49..65]);

    let mut key_rsc = [0u8; 8];
    key_rsc.copy_from_slice(&frame[65..73]);

    let mut mic = [0u8; MIC_LEN];
    mic.copy_from_slice(&frame[81..81 + MIC_LEN]);

    let key_data_len = u16::from_be_bytes([frame[97], frame[98]]) as usize;
    let key_data = if frame.len() >= 99 + key_data_len {
        frame[99..99 + key_data_len].to_vec()
    } else {
        Vec::new()
    };

    Ok(EapolFrame {
        version,
        descriptor_type,
        key_info,
        key_len,
        replay_counter,
        nonce,
        key_iv,
        key_rsc,
        mic,
        key_data,
    })
}
