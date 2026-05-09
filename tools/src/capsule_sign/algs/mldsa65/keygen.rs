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

use crate::algs::traits::KeyPair;
use crate::error::SignError;

use super::ffi;

pub fn from_seed(_seed: &[u8]) -> Result<KeyPair, SignError> {
    Err(SignError::SeedKeygenUnsupported("mldsa65"))
}

pub fn random() -> Result<KeyPair, SignError> {
    let mut pk = vec![0u8; ffi::PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; ffi::SECRET_KEY_BYTES];
    let rc = unsafe { ffi::PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err(SignError::PqcleanFailed("mldsa65 keypair"));
    }
    Ok(KeyPair { pubkey: pk, seed: sk })
}
