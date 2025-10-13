//! NØNOS Module Authentication 

use alloc::{vec::Vec, string::String};
use crate::crypto::{verify_ed25519, blake3_hash, verify_dilithium, TrustedAttestation};
use crate::security::{trusted_keys::get_trusted_keys, attestation::verify_attestation_chain};
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
    pub attestation_chain: Option<TrustedAttestation>,
    pub failure_reason: Option<String>,
}

/// Layered authentication.
pub fn authenticate_module(
    code: &[u8],
    ed25519_signature: &[u8; 64],
    ed25519_pubkey: &[u8; 32],
    dilithium_signature: Option<&[u8]>,
    dilithium_pubkey: Option<&[u8]>,
    attestation: Option<&TrustedAttestation>,
) -> AuthContext {
    let hash = blake3_hash(code);
    let mut ctx = AuthContext {
        verified: false,
        pqc_verified: false,
        attestation_chain: None,
        failure_reason: None,
    };

    // 1. Classical Ed25519/BLAKE3 verification
    match verify_ed25519(&hash, ed25519_signature, ed25519_pubkey) {
        Ok(true) => ctx.verified = true,
        Ok(false) => ctx.failure_reason = Some("Ed25519 verification failed".to_string()),
        Err(e) => ctx.failure_reason = Some(format!("Ed25519 error: {e}")),
    }

    // 2. Post-Quantum Dilithium verification 
    if let (Some(sig), Some(pk)) = (dilithium_signature, dilithium_pubkey) {
        match verify_dilithium(&hash, sig, pk) {
            Ok(true) => ctx.pqc_verified = true,
            Ok(false) => ctx.failure_reason = Some("Dilithium PQC verification failed".to_string()),
            Err(e) => ctx.failure_reason = Some(format!("Dilithium error: {e}")),
        }
    }

    // 3. Attestation chain verification 
    if let Some(att) = attestation {
        if verify_attestation_chain(att, &hash, &get_trusted_keys()) {
            ctx.attestation_chain = Some(att.clone());
        } else {
            ctx.failure_reason = Some("Attestation chain verification failed".to_string());
        }
    }

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
