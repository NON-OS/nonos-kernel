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

use crate::crypto::hash::sha256;
use crate::crypto::rng::fill_random_bytes;

use super::super::types::{KEY_SIZE, SALT_SIZE, KEY_DERIVATION_CONTEXT, secure_zeroize_array};

#[derive(Debug)]
pub struct FileKey {
    pub key: [u8; KEY_SIZE],
    pub salt: [u8; SALT_SIZE],
}

impl FileKey {
    pub fn new(filename: &str) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        fill_random_bytes(&mut salt);
        let key = derive_key(filename, &salt);
        Self { key, salt }
    }

    pub fn secure_clear(&mut self) {
        secure_zeroize_array(&mut self.key);
        secure_zeroize_array(&mut self.salt);
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

pub(crate) fn derive_key(filename: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
    let filename_bytes = filename.as_bytes();
    let total_len = SALT_SIZE + filename_bytes.len() + KEY_DERIVATION_CONTEXT.len();

    let mut input = Vec::with_capacity(total_len);
    input.extend_from_slice(salt);
    input.extend_from_slice(filename_bytes);
    input.extend_from_slice(KEY_DERIVATION_CONTEXT);

    sha256(&input)
}
