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

use nonos_libc::{crypto_x25519_public, crypto_x25519_shared};

use super::types::CryptoError;

pub fn x25519_public(private: &[u8; 32], out: &mut [u8; 32]) -> Result<(), CryptoError> {
    let n = crypto_x25519_public(private.as_ptr(), out.as_mut_ptr());
    if n == out.len() as i64 {
        Ok(())
    } else {
        Err(CryptoError::Ecdh)
    }
}

pub fn x25519_shared(
    private: &[u8; 32],
    public: &[u8; 32],
    out: &mut [u8; 32],
) -> Result<(), CryptoError> {
    let n = crypto_x25519_shared(private.as_ptr(), public.as_ptr(), out.as_mut_ptr());
    if n == out.len() as i64 {
        Ok(())
    } else {
        Err(CryptoError::Ecdh)
    }
}
