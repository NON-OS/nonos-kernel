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

use core::sync::atomic::{compiler_fence, Ordering};
use super::constants::*;
use super::error::{AuthError, AuthResult};
use super::types::{AuthContext, AuthMethod, SignatureData};

pub fn authenticate_module(
    code: &[u8],
    ed25519_signature: Option<&[u8; ED25519_SIGNATURE_SIZE]>,
    ed25519_pubkey: Option<&[u8; ED25519_PUBKEY_SIZE]>,
    dilithium_signature: Option<&[u8]>,
    dilithium_pubkey: Option<&[u8]>,
    attestation_data: Option<&[u8]>,
) -> AuthContext {
    let mut ctx = AuthContext::new();

    if code.is_empty() {
        return ctx;
    }

    let hash = crate::crypto::hash_blake3_hash(code);
    ctx.hash = hash;

    if let (Some(sig), Some(pk)) = (ed25519_signature, ed25519_pubkey) {
        ctx.method = AuthMethod::Ed25519;
        if verify_ed25519(&hash, sig, pk).is_ok() {
            ctx.verified = true;
        }
    } else {
        ctx.verified = true;
        ctx.method = AuthMethod::None;
    }

    #[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
    if let (Some(sig), Some(pk)) = (dilithium_signature, dilithium_pubkey) {
        if verify_dilithium(&hash, sig, pk).is_ok() {
            ctx.pqc_verified = true;
            ctx.method = if ctx.verified { AuthMethod::Hybrid } else { AuthMethod::Dilithium };
        }
    }

    #[cfg(not(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5")))]
    let _ = (dilithium_signature, dilithium_pubkey);

    if let Some(att_data) = attestation_data {
        if !att_data.is_empty() && verify_attestation(code, att_data).is_ok() {
            ctx.attestation_valid = true;
        }
    }

    ctx
}

pub fn verify_signature(code: &[u8], sig_data: &SignatureData) -> AuthResult<()> {
    if code.is_empty() {
        return Err(AuthError::EmptyCode);
    }

    let hash = crate::crypto::hash_blake3_hash(code);
    verify_ed25519(&hash, &sig_data.signature, &sig_data.pubkey)
}

fn verify_ed25519(
    hash: &[u8; BLAKE3_HASH_SIZE],
    signature: &[u8; ED25519_SIGNATURE_SIZE],
    pubkey: &[u8; ED25519_PUBKEY_SIZE],
) -> AuthResult<()> {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);

    let sig = crate::crypto::ed25519::Signature { R: r, S: s };

    if crate::crypto::verify(pubkey, hash, &sig) {
        Ok(())
    } else {
        Err(AuthError::Ed25519VerificationFailed)
    }
}

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
fn verify_dilithium(
    hash: &[u8; BLAKE3_HASH_SIZE],
    signature: &[u8],
    pubkey: &[u8],
) -> AuthResult<()> {
    use crate::crypto::dilithium::{
        dilithium_verify, dilithium_deserialize_public_key, dilithium_deserialize_signature,
        PUBLICKEY_BYTES, SIGNATURE_BYTES,
    };

    if signature.len() != SIGNATURE_BYTES {
        return Err(AuthError::InvalidSignatureLength);
    }
    if pubkey.len() != PUBLICKEY_BYTES {
        return Err(AuthError::InvalidPublicKeyLength);
    }

    let d_pk = dilithium_deserialize_public_key(pubkey)
        .map_err(|_| AuthError::InvalidFormat)?;
    let d_sig = dilithium_deserialize_signature(signature)
        .map_err(|_| AuthError::InvalidFormat)?;

    if dilithium_verify(&d_pk, hash, &d_sig) {
        Ok(())
    } else {
        Err(AuthError::DilithiumVerificationFailed)
    }
}

fn verify_attestation(code: &[u8], attestation: &[u8]) -> AuthResult<()> {
    if attestation.len() < ED25519_SIGNATURE_SIZE {
        return Err(AuthError::AttestationFailed);
    }

    let hash = crate::crypto::hash_blake3_hash(code);
    let trusted_keys = crate::security::nonos_trusted_keys::get_trusted_keys();

    for trusted_key in trusted_keys.iter() {
        if trusted_key.key.len() == ED25519_PUBKEY_SIZE {
            let mut pk = [0u8; ED25519_PUBKEY_SIZE];
            pk.copy_from_slice(&trusted_key.key);

            let mut sig = [0u8; ED25519_SIGNATURE_SIZE];
            sig.copy_from_slice(&attestation[..ED25519_SIGNATURE_SIZE]);

            if verify_ed25519(&hash, &sig, &pk).is_ok() {
                return Ok(());
            }
        }
    }

    Err(AuthError::TrustedKeyNotFound)
}

pub fn erase_auth_context(ctx: &mut AuthContext) {
    ctx.verified = false;
    ctx.pqc_verified = false;
    ctx.attestation_valid = false;
    ctx.method = AuthMethod::None;

    // SAFETY: Volatile writes ensure erasure is not optimized away
    for b in ctx.hash.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}
