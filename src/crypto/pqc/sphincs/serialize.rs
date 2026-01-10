// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::types::{SphincsPublicKey, SphincsSecretKey, SphincsSignature};
use super::{SPHINCS_FORS_SIG_BYTES, SPHINCS_N, SPHINCS_PK_BYTES, SPHINCS_SK_BYTES};

pub fn sphincs_serialize_public_key(pk: &SphincsPublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(SPHINCS_PK_BYTES);
    out.extend_from_slice(&pk.seed);
    out.extend_from_slice(&pk.root);
    out
}

pub fn sphincs_deserialize_public_key(bytes: &[u8]) -> Result<SphincsPublicKey, &'static str> {
    if bytes.len() != SPHINCS_PK_BYTES {
        return Err("Invalid public key length");
    }

    let mut seed = [0u8; SPHINCS_N];
    let mut root = [0u8; SPHINCS_N];
    seed.copy_from_slice(&bytes[0..SPHINCS_N]);
    root.copy_from_slice(&bytes[SPHINCS_N..2 * SPHINCS_N]);

    Ok(SphincsPublicKey { seed, root })
}

pub fn sphincs_serialize_secret_key(sk: &SphincsSecretKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(SPHINCS_SK_BYTES);
    out.extend_from_slice(&sk.sk_seed);
    out.extend_from_slice(&sk.sk_prf);
    out.extend_from_slice(&sk.pk_seed);
    out.extend_from_slice(&sk.pk_root);
    out
}

pub fn sphincs_deserialize_secret_key(bytes: &[u8]) -> Result<SphincsSecretKey, &'static str> {
    if bytes.len() != SPHINCS_SK_BYTES {
        return Err("Invalid secret key length");
    }

    let mut sk_seed = [0u8; SPHINCS_N];
    let mut sk_prf = [0u8; SPHINCS_N];
    let mut pk_seed = [0u8; SPHINCS_N];
    let mut pk_root = [0u8; SPHINCS_N];

    sk_seed.copy_from_slice(&bytes[0..SPHINCS_N]);
    sk_prf.copy_from_slice(&bytes[SPHINCS_N..2 * SPHINCS_N]);
    pk_seed.copy_from_slice(&bytes[2 * SPHINCS_N..3 * SPHINCS_N]);
    pk_root.copy_from_slice(&bytes[3 * SPHINCS_N..4 * SPHINCS_N]);

    Ok(SphincsSecretKey { sk_seed, sk_prf, pk_seed, pk_root })
}

pub fn sphincs_serialize_signature(sig: &SphincsSignature) -> Vec<u8> {
    sig.bytes.clone()
}

pub fn sphincs_deserialize_signature(bytes: &[u8]) -> Result<SphincsSignature, &'static str> {
    if bytes.len() < SPHINCS_N + SPHINCS_FORS_SIG_BYTES {
        return Err("Invalid signature length");
    }
    Ok(SphincsSignature { bytes: bytes.to_vec() })
}
