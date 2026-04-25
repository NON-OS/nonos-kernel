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

use crate::network::nym::crypto::lioness::{lioness_decrypt, lioness_encrypt};
use crate::network::nym::error::NymError;
use crate::network::nym::types::NYM_PAYLOAD_SIZE;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct SphinxPayload {
    pub data: Vec<u8>,
}

pub fn encrypt_payload(plaintext: &[u8], keys: &[[u8; 32]]) -> Result<SphinxPayload, NymError> {
    if plaintext.len() > NYM_PAYLOAD_SIZE {
        return Err(NymError::PacketTooLarge);
    }
    let mut padded = vec![0u8; NYM_PAYLOAD_SIZE];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    padded[plaintext.len()] = 0x80;
    for key in keys.iter().rev() {
        lioness_encrypt(key, &mut padded);
    }
    Ok(SphinxPayload { data: padded })
}

pub fn decrypt_payload(payload: &mut SphinxPayload, key: &[u8; 32]) -> Result<(), NymError> {
    if payload.data.len() < 64 {
        return Err(NymError::InvalidPayload);
    }
    lioness_decrypt(key, &mut payload.data);
    Ok(())
}

pub(crate) fn unpad_payload(data: &[u8]) -> &[u8] {
    for i in (0..data.len()).rev() {
        if data[i] == 0x80 {
            return &data[..i];
        }
        if data[i] != 0 {
            break;
        }
    }
    data
}

impl SphinxPayload {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}
