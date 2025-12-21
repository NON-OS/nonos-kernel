// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
// 
//! Tokens that require multiple signers to be valid (M-of-N threshold).
//! Used for high-security operations requiring consensus.

extern crate alloc;

use alloc::vec::Vec;

use super::{caps_to_bits, default_nonce, Capability};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of signers per token
const MAX_SIGNERS: usize = 16;

/// Maximum threshold (must be <= MAX_SIGNERS)
const MAX_THRESHOLD: usize = MAX_SIGNERS;

// ============================================================================
// Errors
// ============================================================================

/// Multi-signature operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiSigError {
    /// No signers specified
    NoSigners,
    /// Too many signers
    TooManySigners { count: usize, max: usize },
    /// Threshold exceeds signer count
    ThresholdExceedsSigners { threshold: usize, signers: usize },
    /// Threshold is zero
    ZeroThreshold,
    /// Signer already signed
    DuplicateSigner { signer_id: u64 },
    /// Signer not in authorized list
    UnauthorizedSigner { signer_id: u64 },
    /// Insufficient signatures for threshold
    ThresholdNotMet { have: usize, need: usize },
    /// Token has expired
    TokenExpired,
    /// Invalid signature
    InvalidSignature { signer_id: u64 },
}

impl MultiSigError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoSigners => "No signers specified",
            Self::TooManySigners { .. } => "Too many signers",
            Self::ThresholdExceedsSigners { .. } => "Threshold exceeds signer count",
            Self::ZeroThreshold => "Threshold cannot be zero",
            Self::DuplicateSigner { .. } => "Signer already signed",
            Self::UnauthorizedSigner { .. } => "Signer not authorized",
            Self::ThresholdNotMet { .. } => "Insufficient signatures",
            Self::TokenExpired => "Token has expired",
            Self::InvalidSignature { .. } => "Invalid signature",
        }
    }
}

impl core::fmt::Display for MultiSigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSigners => write!(f, "No signers specified"),
            Self::TooManySigners { count, max } => {
                write!(f, "Too many signers: {} (max: {})", count, max)
            }
            Self::ThresholdExceedsSigners { threshold, signers } => {
                write!(
                    f,
                    "Threshold {} exceeds signer count {}",
                    threshold, signers
                )
            }
            Self::ZeroThreshold => write!(f, "Threshold cannot be zero"),
            Self::DuplicateSigner { signer_id } => {
                write!(f, "Signer {} already signed", signer_id)
            }
            Self::UnauthorizedSigner { signer_id } => {
                write!(f, "Signer {} not authorized", signer_id)
            }
            Self::ThresholdNotMet { have, need } => {
                write!(f, "Have {} signatures, need {}", have, need)
            }
            Self::TokenExpired => write!(f, "Token has expired"),
            Self::InvalidSignature { signer_id } => {
                write!(f, "Invalid signature from signer {}", signer_id)
            }
        }
    }
}

// ============================================================================
// Multi-Signature Token
// ============================================================================

/// A capability token requiring multiple signatures
#[derive(Debug, Clone)]
pub struct MultiSigToken {
    /// Owner module ID
    pub owner_module: u64,
    /// Granted capabilities
    pub permissions: Vec<Capability>,
    /// Expiration timestamp (ms since boot)
    pub expires_at_ms: Option<u64>,
    /// Unique nonce for replay protection
    pub nonce: u64,
    /// Required number of valid signatures
    pub threshold: usize,
    /// Authorized signer IDs
    pub authorized_signers: Vec<u64>,
    /// Collected signatures (signer_id, signature)
    signatures: Vec<(u64, [u8; 32])>,
}

impl MultiSigToken {
    /// Check if token has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() >= exp,
            None => false,
        }
    }

    /// Check if token grants a capability
    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.permissions.iter().any(|c| *c == cap)
    }

    /// Get number of collected signatures
    #[inline]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Check if threshold is met
    #[inline]
    pub fn threshold_met(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    /// Get remaining signatures needed
    #[inline]
    pub fn signatures_needed(&self) -> usize {
        self.threshold.saturating_sub(self.signatures.len())
    }

    /// Check if a signer has already signed
    pub fn has_signed(&self, signer_id: u64) -> bool {
        self.signatures.iter().any(|(id, _)| *id == signer_id)
    }

    /// Check if a signer is authorized
    pub fn is_authorized(&self, signer_id: u64) -> bool {
        self.authorized_signers.contains(&signer_id)
    }

    /// Get list of signers who have signed
    pub fn signed_by(&self) -> Vec<u64> {
        self.signatures.iter().map(|(id, _)| *id).collect()
    }

    /// Get list of authorized signers who haven't signed yet
    pub fn pending_signers(&self) -> Vec<u64> {
        self.authorized_signers
            .iter()
            .filter(|id| !self.has_signed(**id))
            .copied()
            .collect()
    }
}

impl core::fmt::Display for MultiSigToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MultiSig[owner:{} caps:{} sigs:{}/{} auth:{}]",
            self.owner_module,
            self.permissions.len(),
            self.signatures.len(),
            self.threshold,
            self.authorized_signers.len()
        )
    }
}

// ============================================================================
// Token Operations
// ============================================================================

/// Compute signature material for a signer
fn signature_material(token: &MultiSigToken, signer_id: u64) -> [u8; 40] {
    let mut mat = [0u8; 40];
    mat[0..8].copy_from_slice(&signer_id.to_le_bytes());
    mat[8..16].copy_from_slice(&token.owner_module.to_le_bytes());
    mat[16..24].copy_from_slice(&caps_to_bits(&token.permissions).to_le_bytes());
    mat[24..32].copy_from_slice(&token.nonce.to_le_bytes());
    mat[32..40].copy_from_slice(&token.expires_at_ms.unwrap_or(0).to_le_bytes());
    mat
}

/// Create a new multi-signature token
///
/// # Arguments
///
/// * `owner` - Owner module ID
/// * `perms` - Capabilities to grant
/// * `threshold` - Required number of signatures (M in M-of-N)
/// * `authorized_signers` - List of authorized signer IDs (N in M-of-N)
/// * `ttl_ms` - Optional time-to-live in milliseconds
///
/// # Returns
///
/// * `Ok(MultiSigToken)` - New unsigned token
/// * `Err(MultiSigError)` - Invalid parameters
pub fn create_multisig_token(
    owner: u64,
    perms: &[Capability],
    threshold: usize,
    authorized_signers: &[u64],
    ttl_ms: Option<u64>,
) -> Result<MultiSigToken, MultiSigError> {
    // Validate threshold
    if threshold == 0 {
        return Err(MultiSigError::ZeroThreshold);
    }

    // Validate signers
    if authorized_signers.is_empty() {
        return Err(MultiSigError::NoSigners);
    }

    if authorized_signers.len() > MAX_SIGNERS {
        return Err(MultiSigError::TooManySigners {
            count: authorized_signers.len(),
            max: MAX_SIGNERS,
        });
    }

    if threshold > authorized_signers.len() {
        return Err(MultiSigError::ThresholdExceedsSigners {
            threshold,
            signers: authorized_signers.len(),
        });
    }

    let expiry = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));

    Ok(MultiSigToken {
        owner_module: owner,
        permissions: perms.to_vec(),
        expires_at_ms: expiry,
        nonce: default_nonce(),
        threshold,
        authorized_signers: authorized_signers.to_vec(),
        signatures: Vec::with_capacity(threshold),
    })
}

/// Add a signature to a multi-sig token
///
/// # Arguments
///
/// * `token` - Token to sign
/// * `signer_id` - ID of the signer
/// * `key` - Signer's 32-byte key
///
/// # Returns
///
/// * `Ok(())` - Signature added
/// * `Err(MultiSigError)` - Signing failed
pub fn add_signature(
    token: &mut MultiSigToken,
    signer_id: u64,
    key: &[u8; 32],
) -> Result<(), MultiSigError> {
    // Check authorization
    if !token.is_authorized(signer_id) {
        return Err(MultiSigError::UnauthorizedSigner { signer_id });
    }

    // Check for duplicate
    if token.has_signed(signer_id) {
        return Err(MultiSigError::DuplicateSigner { signer_id });
    }

    // Check expiry
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }

    // Compute signature
    let mat = signature_material(token, signer_id);
    let mac = blake3::keyed_hash(key, &mat);

    token.signatures.push((signer_id, *mac.as_bytes()));
    Ok(())
}

/// Verify a multi-sig token has sufficient valid signatures
///
/// # Arguments
///
/// * `token` - Token to verify
/// * `keys` - Mapping of signer IDs to their keys
///
/// # Returns
///
/// * `Ok(true)` - Threshold met with valid signatures
/// * `Ok(false)` - Threshold not met (but no errors)
/// * `Err(MultiSigError)` - Verification error
pub fn verify_multisig(
    token: &MultiSigToken,
    keys: &[(&u64, &[u8; 32])],
) -> Result<bool, MultiSigError> {
    // Check expiry
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }

    let mut valid_count = 0;

    for (signer_id, sig) in &token.signatures {
        // Find the key for this signer
        let key = keys.iter().find(|(id, _)| **id == *signer_id);

        if let Some((_, key)) = key {
            // Verify signature
            let mat = signature_material(token, *signer_id);
            let expected = blake3::keyed_hash(key, &mat);

            if sig == expected.as_bytes() {
                valid_count += 1;
            }
        }
    }

    Ok(valid_count >= token.threshold)
}

/// Strict verification with detailed error on failure
pub fn verify_multisig_strict(
    token: &MultiSigToken,
    keys: &[(&u64, &[u8; 32])],
) -> Result<(), MultiSigError> {
    if token.is_expired() {
        return Err(MultiSigError::TokenExpired);
    }

    let mut valid_count = 0;

    for (signer_id, sig) in &token.signatures {
        let key = keys.iter().find(|(id, _)| **id == *signer_id);

        if let Some((_, key)) = key {
            let mat = signature_material(token, *signer_id);
            let expected = blake3::keyed_hash(key, &mat);

            if sig == expected.as_bytes() {
                valid_count += 1;
            } else {
                return Err(MultiSigError::InvalidSignature {
                    signer_id: *signer_id,
                });
            }
        }
    }

    if valid_count < token.threshold {
        return Err(MultiSigError::ThresholdNotMet {
            have: valid_count,
            need: token.threshold,
        });
    }

    Ok(())
}

/// Get maximum allowed signers
#[inline]
pub const fn max_signers() -> usize {
    MAX_SIGNERS
}

/// Get maximum allowed threshold
#[inline]
pub const fn max_threshold() -> usize {
    MAX_THRESHOLD
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_create_token_validation() {
        // Zero threshold
        let result = create_multisig_token(1, &[], 0, &[1, 2], None);
        assert_eq!(result.unwrap_err(), MultiSigError::ZeroThreshold);

        // No signers
        let result = create_multisig_token(1, &[], 1, &[], None);
        assert_eq!(result.unwrap_err(), MultiSigError::NoSigners);

        // Threshold exceeds signers
        let result = create_multisig_token(1, &[], 3, &[1, 2], None);
        assert!(matches!(
            result.unwrap_err(),
            MultiSigError::ThresholdExceedsSigners { .. }
        ));
    }

    #[test]
    fn test_token_display() {
        let token = create_multisig_token(42, &[Capability::IPC], 2, &[1, 2, 3], None).unwrap();
        let s = alloc::format!("{}", token);
        assert!(s.contains("owner:42"));
        assert!(s.contains("caps:1"));
        assert!(s.contains("sigs:0/2"));
        assert!(s.contains("auth:3"));
    }

    #[test]
    fn test_token_helpers() {
        let token = create_multisig_token(1, &[Capability::IPC], 2, &[10, 20, 30], None).unwrap();

        assert!(!token.threshold_met());
        assert_eq!(token.signatures_needed(), 2);
        assert!(!token.has_signed(10));
        assert!(token.is_authorized(10));
        assert!(!token.is_authorized(99));
        assert_eq!(token.pending_signers(), vec![10, 20, 30]);
    }

    #[test]
    fn test_error_display() {
        let e = MultiSigError::ThresholdNotMet { have: 1, need: 2 };
        let s = alloc::format!("{}", e);
        assert!(s.contains("1"));
        assert!(s.contains("2"));

        let e = MultiSigError::DuplicateSigner { signer_id: 42 };
        assert!(alloc::format!("{}", e).contains("42"));
    }

    #[test]
    fn test_grants() {
        let token =
            create_multisig_token(1, &[Capability::IPC, Capability::Memory], 1, &[1], None)
                .unwrap();

        assert!(token.grants(Capability::IPC));
        assert!(token.grants(Capability::Memory));
        assert!(!token.grants(Capability::Network));
    }

    #[test]
    fn test_max_constants() {
        assert_eq!(max_signers(), MAX_SIGNERS);
        assert_eq!(max_threshold(), MAX_THRESHOLD);
    }
}
