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

use crate::crypto::asymmetric::ed25519;
use crate::crypto::application::vault;
use crate::crypto::hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCryptoError {
    KeyNotFound,
    PermissionDenied,
    InvalidArgument,
    BufferTooSmall,
    AlgorithmNotSupported,
    IoError,
}

pub fn syscall_blake3_hash(data: &[u8]) -> Result<u64, SyscallCryptoError> {
    let hash_result = hash::blake3::blake3_hash(data);
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&hash_result[..8]);
    Ok(u64::from_le_bytes(id_bytes))
}

pub fn sha256_hash(data: &[u8]) -> Result<u64, SyscallCryptoError> {
    let hash_val = hash::sha256(data);
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&hash_val[..8]);
    Ok(u64::from_le_bytes(id_bytes))
}

pub fn sha512_hash(data: &[u8]) -> Result<u64, SyscallCryptoError> {
    let hash_result = hash::sha512(data);
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&hash_result[..8]);
    Ok(u64::from_le_bytes(id_bytes))
}

pub fn sign_message(key_id: u32, message: &[u8], sig_buffer: &mut [u8]) -> Result<usize, SyscallCryptoError> {
    if sig_buffer.len() < 64 {
        return Err(SyscallCryptoError::BufferTooSmall);
    }

    let private_key = match vault::get_signing_key(key_id) {
        Some(pk) => pk,
        None => return Err(SyscallCryptoError::KeyNotFound),
    };

    let keypair = ed25519::KeyPair::from_seed(private_key);
    let signature = ed25519::sign(&keypair, message);
    sig_buffer[..64].copy_from_slice(&signature.to_bytes());

    Ok(64)
}

pub fn verify_signature_syscall(key_id: u32, message: &[u8], signature: &[u8]) -> Result<bool, SyscallCryptoError> {
    if signature.len() != 64 {
        return Err(SyscallCryptoError::InvalidArgument);
    }

    let public_key = match vault::get_public_key(key_id) {
        Some(pk) => pk,
        None => return Err(SyscallCryptoError::KeyNotFound),
    };

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature);
    let sig_struct = ed25519::Signature::from_bytes(&sig_array);

    Ok(ed25519::verify(&public_key, message, &sig_struct))
}
