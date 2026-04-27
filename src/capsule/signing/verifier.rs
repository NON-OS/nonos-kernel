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

use super::keys::{self, PublicKey};
use super::signer::Signature;
use crate::crypto::ed25519::Signature as Ed25519Sig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    InvalidSignature,
    InvalidPublicKey,
    UntrustedKey,
    DataTooShort,
}

pub fn verify(
    message: &[u8],
    signature: &Signature,
    pubkey: &PublicKey,
) -> Result<(), VerifyError> {
    let sig = Ed25519Sig::from_bytes(signature);
    if !crate::crypto::ed25519::verify(pubkey, message, &sig) {
        return Err(VerifyError::InvalidSignature);
    }
    Ok(())
}

pub fn verify_trusted(
    message: &[u8],
    signature: &Signature,
    pubkey: &PublicKey,
) -> Result<(), VerifyError> {
    if !keys::is_trusted(pubkey) {
        return Err(VerifyError::UntrustedKey);
    }
    verify(message, signature, pubkey)
}

pub fn verify_capsule(data: &[u8], pubkey: &PublicKey) -> Result<(), VerifyError> {
    if data.len() < 64 {
        return Err(VerifyError::DataTooShort);
    }
    let sig_start = data.len() - 64;
    let message = &data[..sig_start];
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&data[sig_start..]);
    verify(message, &sig, pubkey)
}

pub fn verify_capsule_trusted(data: &[u8], pubkey: &PublicKey) -> Result<(), VerifyError> {
    if !keys::is_trusted(pubkey) {
        return Err(VerifyError::UntrustedKey);
    }
    verify_capsule(data, pubkey)
}

pub fn extract_signature(data: &[u8]) -> Result<(Signature, &[u8]), VerifyError> {
    if data.len() < 64 {
        return Err(VerifyError::DataTooShort);
    }
    let sig_start = data.len() - 64;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&data[sig_start..]);
    Ok((sig, &data[..sig_start]))
}
