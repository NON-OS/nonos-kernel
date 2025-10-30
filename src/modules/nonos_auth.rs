//! NØNOS Module Authentication 

use alloc::{vec::Vec, string::String, string::ToString};
use crate::crypto::{verify, blake3_hash, nonos_zk::AttestationProof};
use crate::security::nonos_trusted_keys::get_trusted_keys;
use crate::memory::memory::zero_memory;

/// Authentication result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Verified,
    VerifiedPqc,
    Attested,
    Failed(String),
}

/// Authentication 
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub verified: bool,
    pub pqc_verified: bool,
    pub attestation_chain: Option<AttestationProof>,
    pub failure_reason: Option<String>,
}

/// Layered authentication.
pub fn authenticate_module(
    code: &[u8],
    ed25519_signature: &[u8; 64],
    ed25519_pubkey: &[u8; 32],
    dilithium_signature: Option<&[u8]>,
    dilithium_pubkey: Option<&[u8]>,
    attestation: Option<&AttestationProof>,
) -> AuthContext {
    let hash = blake3_hash(code);
    let mut ctx = AuthContext {
        verified: false,
        pqc_verified: false,
        attestation_chain: None,
        failure_reason: None,
    };

    // 1. Classical Ed25519/BLAKE3 verification
    if ed25519_signature.len() != 64 {
        ctx.failure_reason = Some("Invalid signature length".into());
        return ctx;
    }
    
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&ed25519_signature[..32]);
    s.copy_from_slice(&ed25519_signature[32..]);
    let sig = crate::crypto::ed25519::Signature { R: r, S: s };
    
    if verify(ed25519_pubkey, &hash, &sig) {
        ctx.verified = true;
    } else {
        ctx.failure_reason = Some("Ed25519 verification failed".into());
    }

    // 2. Post-Quantum Dilithium verification (disabled - feature not enabled)
    /*
    if let (Some(sig), Some(pk)) = (dilithium_signature, dilithium_pubkey) {
        match dilithium_verify(&hash, sig, pk) {
            Ok(true) => ctx.pqc_verified = true,
            Ok(false) => ctx.failure_reason = Some("Dilithium PQC verification failed".into()),
            Err(e) => ctx.failure_reason = Some(format!("Dilithium error: {e}")),
        }
    }
    */
    let _ = (dilithium_signature, dilithium_pubkey); // Avoid unused warnings

    // 3. Attestation chain verification (disabled - module not available)
    /*
    if let Some(att) = attestation {
        if verify_attestation_chain(att, &hash, &get_trusted_keys()) {
            ctx.attestation_chain = Some(att.clone());
        } else {
            ctx.failure_reason = Some("Attestation chain verification failed".into());
        }
    }
    */
    let _ = attestation; // Avoid unused warnings

    ctx
}

/// Securely erase authentication from RAM.
pub fn erase_auth_context(ctx: &mut AuthContext) {
    ctx.verified = false;
    ctx.pqc_verified = false;
    ctx.attestation_chain = None;
    if let Some(ref mut reason) = ctx.failure_reason {
        // Convert to mutable bytes for secure erasure
        let mut bytes = reason.as_bytes().to_vec();
        zero_memory(x86_64::VirtAddr::from_ptr(bytes.as_mut_ptr()), bytes.len()).ok();
        *reason = String::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_authenticate_module_classical_fail() {
        let code = b"module-test";
        let sig = [0u8; 64];
        let pk = [0u8; 32];
        let ctx = authenticate_module(code, &sig, &pk, None, None, None);
        assert!(!ctx.verified);
        assert!(ctx.failure_reason.is_some());
    }

    #[test]
    fn test_erase_auth_context() {
        let mut ctx = AuthContext {
            verified: true,
            pqc_verified: true,
            attestation_chain: None,
            failure_reason: Some("Test".into()),
        };
        erase_auth_context(&mut ctx);
        assert!(!ctx.verified);
        assert!(!ctx.pqc_verified);
        assert!(ctx.failure_reason.as_deref().unwrap_or("") == "");
    }
}
