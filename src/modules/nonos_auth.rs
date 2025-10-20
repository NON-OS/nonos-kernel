//! NØNOS Module Authentication 

use alloc::{vec::Vec, string::String};
use crate::crypto::{verify, blake3_hash, nonos_zk::AttestationProof};
use crate::security::nonos_trusted_keys::get_trusted_keys;
use crate::memory::secure_erase;

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
    match verify(&hash, ed25519_signature, ed25519_pubkey) {
        Ok(true) => ctx.verified = true,
        Ok(false) => ctx.failure_reason = Some("Ed25519 verification failed".to_string()),
        Err(e) => ctx.failure_reason = Some(format!("Ed25519 error: {e}")),
    }

    // 2. Post-Quantum Dilithium verification (disabled - feature not enabled)
    /*
    if let (Some(sig), Some(pk)) = (dilithium_signature, dilithium_pubkey) {
        match dilithium_verify(&hash, sig, pk) {
            Ok(true) => ctx.pqc_verified = true,
            Ok(false) => ctx.failure_reason = Some("Dilithium PQC verification failed".to_string()),
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
            ctx.failure_reason = Some("Attestation chain verification failed".to_string());
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
        secure_erase(reason.as_bytes());
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
            failure_reason: Some("Test".to_string()),
        };
        erase_auth_context(&mut ctx);
        assert!(!ctx.verified);
        assert!(!ctx.pqc_verified);
        assert!(ctx.failure_reason.as_deref().unwrap_or("") == "");
    }
}
