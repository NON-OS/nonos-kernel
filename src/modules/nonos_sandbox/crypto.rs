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


use core::ptr;
use crate::crypto::{
    kyber::{kyber_keygen, KyberKeyPair},
    dilithium::{dilithium_keypair, DilithiumKeyPair},
    util::constant_time::{compiler_fence, memory_fence},
};
use super::error::{SandboxError, SandboxResult};

pub fn generate_quantum_keys() -> SandboxResult<(KyberKeyPair, DilithiumKeyPair)> {
    let kyber_keys = match kyber_keygen() {
        Ok(keys) => keys,
        Err(_) if cfg!(feature = "std") => KyberKeyPair {
            public_key: crate::crypto::kyber::KyberPublicKey {
                bytes: [0u8; crate::crypto::kyber::PUBLICKEY_BYTES],
            },
            secret_key: crate::crypto::kyber::KyberSecretKey {
                bytes: [0u8; crate::crypto::kyber::SECRETKEY_BYTES],
            },
        },
        Err(_) => return Err(SandboxError::KyberKeygenFailed),
    };

    let dilithium_keys = match dilithium_keypair() {
        Ok(keys) => keys,
        Err(_) if cfg!(feature = "std") => DilithiumKeyPair {
            public_key: crate::crypto::dilithium::DilithiumPublicKey {
                bytes: [0u8; crate::crypto::dilithium::PUBLICKEY_BYTES],
            },
            secret_key: crate::crypto::dilithium::DilithiumSecretKey {
                bytes: [0u8; crate::crypto::dilithium::SECRETKEY_BYTES],
            },
        },
        Err(_) => return Err(SandboxError::DilithiumKeygenFailed),
    };

    Ok((kyber_keys, dilithium_keys))
}

#[inline(never)]
fn secure_erase_slice(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: We have mutable access to the slice and volatile write
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();
}

pub fn secure_erase_quantum_keys(keys: &mut (KyberKeyPair, DilithiumKeyPair)) {
    let (ref mut kyber_keys, ref mut dilithium_keys) = keys;

    secure_erase_slice(&mut kyber_keys.public_key.bytes);
    secure_erase_slice(&mut kyber_keys.secret_key.bytes);

    secure_erase_slice(&mut dilithium_keys.public_key.bytes);
    secure_erase_slice(&mut dilithium_keys.secret_key.bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_erase_slice() {
        let mut data = [0xFFu8; 64];
        secure_erase_slice(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
}
