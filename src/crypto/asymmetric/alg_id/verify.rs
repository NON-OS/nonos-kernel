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

use crate::crypto::asymmetric::ed25519::{self as ed25519, Signature as Ed25519Signature};
use crate::crypto::pqc::ml_dsa_65::{
    ml_dsa_65_deserialize_public_key, ml_dsa_65_deserialize_signature, ml_dsa_65_verify,
};

use super::lengths::{pubkey_len, sig_len};
use super::types::{AlgId, AlgIdError};

pub fn verify(
    alg: AlgId,
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, AlgIdError> {
    let want_pk = pubkey_len(alg);
    if pubkey.len() != want_pk {
        return Err(AlgIdError::PubkeyLen { alg, expected: want_pk, got: pubkey.len() });
    }
    let want_sig = sig_len(alg);
    if sig.len() != want_sig {
        return Err(AlgIdError::SigLen { alg, expected: want_sig, got: sig.len() });
    }
    match alg {
        AlgId::Ed25519 => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(pubkey);
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(sig);
            Ok(ed25519::verify(&pk, msg, &Ed25519Signature::from_bytes(&sig_arr)))
        }
        AlgId::MlDsa65 => {
            let pk = match ml_dsa_65_deserialize_public_key(pubkey) {
                Ok(k) => k,
                Err(_) => return Ok(false),
            };
            let s = match ml_dsa_65_deserialize_signature(sig) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(ml_dsa_65_verify(&pk, msg, &s))
        }
        AlgId::MlDsa44 | AlgId::MlDsa87 => Err(AlgIdError::Unsupported(alg)),
    }
}
