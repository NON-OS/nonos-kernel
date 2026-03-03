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


use spin::Once;
use crate::network::onion::OnionError;

pub trait CryptoProvider: Sync + Send {
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), OnionError>;

    fn blake3(&self, data: &[u8], out32: &mut [u8; 32]);

    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]);

    fn hkdf_sha256_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]);

    fn x25519_generate_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError>;

    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError>;

    fn aes128_ctr_apply(&self, key: &[u8; 16], iv: &[u8; 16], counter: u128, inout: &mut [u8]);

    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc = 0u8;
        for i in 0..a.len() {
            acc |= a[i] ^ b[i];
        }
        acc == 0
    }
}

static CRYPTO: Once<&'static dyn CryptoProvider> = Once::new();

struct FallbackProvider;

impl CryptoProvider for FallbackProvider {
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), OnionError> {
        crate::crypto::rng::fill_random_bytes(out);
        Ok(())
    }

    fn blake3(&self, data: &[u8], out32: &mut [u8; 32]) {
        *out32 = crate::crypto::hash::blake3::blake3_hash(data);
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]) {
        *out32 = crate::crypto::hmac::hmac_sha256(key, data);
    }

    fn hkdf_sha256_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
        if let Ok(expanded) = crate::crypto::hmac::hkdf_expand(prk, info, out.len()) {
            out.copy_from_slice(&expanded[..out.len()]);
        }
    }

    fn x25519_generate_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError> {
        let (public, secret) = crate::crypto::asymmetric::curve25519::x25519_keypair()
            .map_err(|_| OnionError::CryptoError)?;
        Ok((secret, public))
    }

    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError> {
        Ok(crate::crypto::asymmetric::curve25519::x25519(sk, pk))
    }

    fn aes128_ctr_apply(&self, key: &[u8; 16], iv: &[u8; 16], counter: u128, inout: &mut [u8]) {
        crate::crypto::symmetric::aes::aes128_ctr_apply(key, iv, counter, inout);
    }
}

static FALLBACK_PROVIDER: FallbackProvider = FallbackProvider;

pub fn init_onion_crypto_provider(p: &'static dyn CryptoProvider) {
    CRYPTO.call_once(|| p);
}

#[inline]
pub fn provider() -> &'static dyn CryptoProvider {
    CRYPTO.call_once(|| &FALLBACK_PROVIDER as &'static dyn CryptoProvider);
    *CRYPTO.get().unwrap()
}
