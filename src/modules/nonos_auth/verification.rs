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


use alloc::string::String;
use crate::crypto::{
    verify,
    hash_blake3_hash as blake3_hash,
    nonos_zk::{AttestationProof, verify_attestation},
    util::constant_time::{compiler_fence, memory_fence},
};
use crate::security::trusted_keys::get_trusted_keys;
use core::ptr;

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
use crate::crypto::dilithium::{
    dilithium_verify, dilithium_deserialize_public_key, dilithium_deserialize_signature,
    PUBLICKEY_BYTES as DILITHIUM_PK_BYTES, SIGNATURE_BYTES as DILITHIUM_SIG_BYTES,
};

use super::types::AuthContext;

pub fn authenticate_module(
    code: &[u8],
    ed25519_signature: &[u8; 64],
    ed25519_pubkey: &[u8; 32],
    dilithium_signature: Option<&[u8]>,
    dilithium_pubkey: Option<&[u8]>,
    attestation: Option<&AttestationProof>,
) -> AuthContext {
    let hash = blake3_hash(code);

    let mut ctx = AuthContext::new();

    ctx = verify_ed25519(&hash, ed25519_signature, ed25519_pubkey, ctx);

    #[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
    {
        ctx = verify_dilithium(&hash, dilithium_signature, dilithium_pubkey, ctx);
    }

    #[cfg(not(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5")))]
    {
        let _ = (dilithium_signature, dilithium_pubkey);
    }

    if let Some(att) = attestation {
        ctx = verify_attestation_chain(code, att, ctx);
    }

    ctx
}

fn verify_ed25519(
    hash: &[u8; 32],
    signature: &[u8; 64],
    pubkey: &[u8; 32],
    mut ctx: AuthContext,
) -> AuthContext {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);

    let sig = crate::crypto::ed25519::Signature { R: r, S: s };

    if verify(pubkey, hash, &sig) {
        ctx.verified = true;
    } else {
        if ctx.failure_reason.is_none() {
            ctx.failure_reason = Some("Ed25519 verification failed".into());
        }
    }

    ctx
}

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
fn verify_dilithium(
    hash: &[u8; 32],
    signature: Option<&[u8]>,
    pubkey: Option<&[u8]>,
    mut ctx: AuthContext,
) -> AuthContext {
    let (Some(sig), Some(pk)) = (signature, pubkey) else {
        return ctx;
    };

    if sig.len() != DILITHIUM_SIG_BYTES {
        ctx.failure_reason = Some("Invalid Dilithium signature length".into());
        return ctx;
    }
    if pk.len() != DILITHIUM_PK_BYTES {
        ctx.failure_reason = Some("Invalid Dilithium key length".into());
        return ctx;
    }

    match (
        dilithium_deserialize_public_key(pk),
        dilithium_deserialize_signature(sig),
    ) {
        (Ok(d_pk), Ok(d_sig)) => {
            if dilithium_verify(&d_pk, hash, &d_sig) {
                ctx.pqc_verified = true;
            } else {
                ctx.failure_reason = Some("Dilithium verification failed".into());
            }
        }
        _ => {
            ctx.failure_reason = Some("Invalid Dilithium key/signature format".into());
        }
    }

    ctx
}

fn verify_attestation_chain(
    code: &[u8],
    attestation: &AttestationProof,
    mut ctx: AuthContext,
) -> AuthContext {
    let trusted_keys = get_trusted_keys();

    for trusted_key in trusted_keys.iter() {
        if trusted_key.key.len() != 32 {
            continue;
        }

        let mut pk = [0u8; 32];
        pk.copy_from_slice(&trusted_key.key);

        if verify_attestation(code, &pk, attestation) {
            ctx.attestation_chain = Some(*attestation);
            return ctx;
        }
    }

    if ctx.failure_reason.is_none() {
        ctx.failure_reason = Some("Attestation chain verification failed".into());
    }

    ctx
}

pub fn erase_auth_context(ctx: &mut AuthContext) {
    ctx.verified = false;
    ctx.pqc_verified = false;
    ctx.attestation_chain = None;

    if let Some(ref mut reason) = ctx.failure_reason {
        // SAFETY: We have mutable access and will replace the string afterward
        let bytes = unsafe { reason.as_bytes_mut() };
        for b in bytes.iter_mut() {
            unsafe { ptr::write_volatile(b, 0) };
        }
        compiler_fence();
        memory_fence();
        *reason = String::new();
    }

    ctx.failure_reason = None;
}

pub fn verify_signature_constant_time(
    code: &[u8],
    signature: &[u8; 64],
    pubkey: &[u8; 32],
) -> bool {
    let hash = blake3_hash(code);

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);

    let sig = crate::crypto::ed25519::Signature { R: r, S: s };

    verify(pubkey, &hash, &sig)
}
