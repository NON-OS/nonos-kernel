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

use super::super::constants::{HASH_OUTPUT_SIZE, KDF_LABEL_PREFIX};
use super::super::error::KaslrResult;
use super::entropy::secure_hash;
use super::init::{boot_nonce, get_slide};

pub fn derive_subkey(label: &[u8], output: &mut [u8]) -> KaslrResult<()> {
    let nonce = boot_nonce()?;
    let slide = get_slide();

    let mut input = alloc::vec::Vec::new();
    input.extend_from_slice(KDF_LABEL_PREFIX);
    input.extend_from_slice(label);
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(&slide.to_le_bytes());

    let key_hash = secure_hash(&input);

    let mut offset = 0;
    while offset < output.len() {
        let remaining = output.len() - offset;
        let copy_len = core::cmp::min(HASH_OUTPUT_SIZE, remaining);
        output[offset..offset + copy_len].copy_from_slice(&key_hash[..copy_len]);
        offset += copy_len;

        if offset < output.len() {
            let mut expanded_input = input.clone();
            expanded_input.extend_from_slice(&(offset as u64).to_le_bytes());
            let next_hash = secure_hash(&expanded_input);
            let copy_len = core::cmp::min(HASH_OUTPUT_SIZE, output.len() - offset);
            output[offset..offset + copy_len].copy_from_slice(&next_hash[..copy_len]);
            offset += copy_len;
        }
    }
    Ok(())
}
