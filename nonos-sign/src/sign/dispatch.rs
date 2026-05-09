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

use crate::algs::ed25519::Ed25519;
use crate::algs::mldsa65::MlDsa65;
use crate::algs::traits::{Signer, Verifier};
use crate::algs::AlgId;
use crate::error::SignError;

pub fn sign_with(alg: AlgId, seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, SignError> {
    match alg {
        AlgId::Ed25519 => Ed25519::sign(seed, msg),
        AlgId::MlDsa65 => MlDsa65::sign(seed, msg),
        other => Err(SignError::UnsupportedAlg(other.label().to_string())),
    }
}

pub fn verify_with(
    alg: AlgId,
    pubkey: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, SignError> {
    match alg {
        AlgId::Ed25519 => <Ed25519 as Verifier>::verify(pubkey, msg, sig),
        AlgId::MlDsa65 => <MlDsa65 as Verifier>::verify(pubkey, msg, sig),
        other => Err(SignError::UnsupportedAlg(other.label().to_string())),
    }
}
