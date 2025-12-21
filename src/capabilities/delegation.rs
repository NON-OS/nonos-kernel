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
//! Capability Delegation

extern crate alloc;

use alloc::vec::Vec;

use super::{caps_to_bits, signing_key, Capability, CapabilityToken};

// ============================================================================
// Errors
// ============================================================================

/// Delegation operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationError {
    /// Signing key not available
    MissingSigningKey,
    /// Parent token is invalid
    InvalidParentToken,
    /// Parent token has expired
    ParentExpired,
    /// Attempted to delegate capability not held by parent
    CapabilityNotHeld,
    /// Delegation has expired
    DelegationExpired,
    /// Signature verification failed
    InvalidSignature,
    /// No capabilities specified
    NoCapabilities,
}

impl DelegationError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingSigningKey => "Signing key not available",
            Self::InvalidParentToken => "Parent token is invalid",
            Self::ParentExpired => "Parent token has expired",
            Self::CapabilityNotHeld => "Cannot delegate capability not held",
            Self::DelegationExpired => "Delegation has expired",
            Self::InvalidSignature => "Signature verification failed",
            Self::NoCapabilities => "No capabilities specified",
        }
    }
}

impl core::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Delegation Structure
// ============================================================================

/// A delegation of capabilities from one module to another
///
/// Represents a signed grant of a subset of capabilities from
/// a parent token holder to a delegatee module.
#[derive(Debug, Clone)]
pub struct Delegation {
    /// Module ID granting the delegation
    pub delegator: u64,
    /// Module ID receiving the delegation
    pub delegatee: u64,
    /// Capabilities being delegated
    pub capabilities: Vec<Capability>,
    /// Expiration timestamp (ms since boot), None = no expiry
    pub expires_at_ms: Option<u64>,
    /// Parent token nonce (for verification)
    pub parent_nonce: u64,
    /// Cryptographic signature (BLAKE3 keyed hash)
    pub signature: [u8; 64],
}

impl Delegation {
    /// Check if delegation has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() >= exp,
            None => false,
        }
    }

    /// Check if delegation is still valid (not expired)
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Get remaining time until expiry in milliseconds
    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms.map(|exp| {
            let now = crate::time::timestamp_millis();
            exp.saturating_sub(now)
        })
    }

    /// Check if delegation grants a specific capability
    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.capabilities.iter().any(|c| *c == cap)
    }

    /// Get number of delegated capabilities
    #[inline]
    pub fn capability_count(&self) -> usize {
        self.capabilities.len()
    }
}

impl core::fmt::Display for Delegation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Delegation[{}->{} caps:{} exp:{}]",
            self.delegator,
            self.delegatee,
            self.capabilities.len(),
            match self.expires_at_ms {
                Some(exp) => alloc::format!("{}ms", exp),
                None => alloc::string::String::from("never"),
            }
        )
    }
}

// ============================================================================
// Delegation Operations
// ============================================================================

/// Compute delegation signature material
fn delegation_material(d: &Delegation, parent_nonce: u64) -> [u8; 48] {
    let mut mat = [0u8; 48];
    mat[0..8].copy_from_slice(&parent_nonce.to_le_bytes());
    mat[8..16].copy_from_slice(&d.delegator.to_le_bytes());
    mat[16..24].copy_from_slice(&d.delegatee.to_le_bytes());
    mat[24..32].copy_from_slice(&caps_to_bits(&d.capabilities).to_le_bytes());
    mat[32..40].copy_from_slice(&d.expires_at_ms.unwrap_or(0).to_le_bytes());
    mat[40..48].copy_from_slice(&d.parent_nonce.to_le_bytes());
    mat
}

/// Create a delegation from a parent token to a delegatee module
///
/// # Arguments
///
/// * `parent` - The parent capability token (delegator's token)
/// * `delegatee` - Module ID receiving the delegation
/// * `caps` - Capabilities to delegate (must be subset of parent's)
/// * `ttl_ms` - Optional time-to-live in milliseconds
///
/// # Returns
///
/// * `Ok(Delegation)` - Signed delegation
/// * `Err(DelegationError)` - Creation failed
///
/// # Errors
///
/// - `MissingSigningKey` - Kernel signing key not set
/// - `InvalidParentToken` - Parent token signature is invalid
/// - `ParentExpired` - Parent token has expired
/// - `CapabilityNotHeld` - Trying to delegate a capability parent doesn't have
/// - `NoCapabilities` - Empty capability list
pub fn create_delegation(
    parent: &CapabilityToken,
    delegatee: u64,
    caps: &[Capability],
    ttl_ms: Option<u64>,
) -> Result<Delegation, DelegationError> {
    // Validate inputs
    if caps.is_empty() {
        return Err(DelegationError::NoCapabilities);
    }

    // Check parent token is valid
    if !parent.is_valid() {
        if !parent.not_expired() {
            return Err(DelegationError::ParentExpired);
        }
        return Err(DelegationError::InvalidParentToken);
    }

    // Check all requested capabilities are held by parent
    for cap in caps {
        if !parent.grants(*cap) {
            return Err(DelegationError::CapabilityNotHeld);
        }
    }

    // Compute expiry (cannot exceed parent's expiry)
    let now = crate::time::timestamp_millis();
    let mut expiry = ttl_ms.map(|t| now.saturating_add(t));

    // Cap at parent's expiry if parent has one
    if let Some(parent_exp) = parent.expires_at_ms {
        expiry = Some(match expiry {
            Some(e) => e.min(parent_exp),
            None => parent_exp,
        });
    }

    let mut delegation = Delegation {
        delegator: parent.owner_module,
        delegatee,
        capabilities: caps.to_vec(),
        expires_at_ms: expiry,
        parent_nonce: parent.nonce,
        signature: [0u8; 64],
    };

    sign_delegation(&mut delegation)?;
    Ok(delegation)
}

/// Sign a delegation using the kernel signing key
///
/// # Arguments
///
/// * `d` - Delegation to sign (signature field will be filled)
///
/// # Returns
///
/// * `Ok(())` - Signature computed and stored
/// * `Err(DelegationError::MissingSigningKey)` - No signing key available
pub fn sign_delegation(d: &mut Delegation) -> Result<(), DelegationError> {
    let key = signing_key().ok_or(DelegationError::MissingSigningKey)?;

    let mat = delegation_material(d, d.parent_nonce);

    // Compute dual MAC for 64-byte signature
    let mac1 = blake3::keyed_hash(key, &mat);
    let mut hasher2 = blake3::Hasher::new_keyed(key);
    hasher2.update(&mat);
    hasher2.update(b"DELEG");
    let mac2 = hasher2.finalize();

    d.signature[..32].copy_from_slice(mac1.as_bytes());
    d.signature[32..].copy_from_slice(mac2.as_bytes());

    Ok(())
}

/// Verify a delegation's signature against a parent token
///
/// # Arguments
///
/// * `d` - Delegation to verify
/// * `parent` - Parent token that created the delegation
///
/// # Returns
///
/// `true` if signature is valid and delegation hasn't expired
pub fn verify_delegation(d: &Delegation, parent: &CapabilityToken) -> bool {
    // Check expiry
    if d.is_expired() {
        return false;
    }

    // Check parent nonce matches
    if d.parent_nonce != parent.nonce {
        return false;
    }

    // Check delegator matches parent owner
    if d.delegator != parent.owner_module {
        return false;
    }

    // Verify signature
    let Some(key) = signing_key() else {
        return false;
    };

    let mat = delegation_material(d, parent.nonce);

    let mac1 = blake3::keyed_hash(key, &mat);
    let mut hasher2 = blake3::Hasher::new_keyed(key);
    hasher2.update(&mat);
    hasher2.update(b"DELEG");
    let mac2 = hasher2.finalize();

    // Verify both halves
    d.signature[..32] == *mac1.as_bytes() && d.signature[32..] == *mac2.as_bytes()
}

/// Full delegation verification with detailed error
///
/// Like `verify_delegation` but returns specific error on failure.
pub fn verify_delegation_strict(
    d: &Delegation,
    parent: &CapabilityToken,
) -> Result<(), DelegationError> {
    if d.is_expired() {
        return Err(DelegationError::DelegationExpired);
    }

    if d.parent_nonce != parent.nonce || d.delegator != parent.owner_module {
        return Err(DelegationError::InvalidParentToken);
    }

    let Some(key) = signing_key() else {
        return Err(DelegationError::MissingSigningKey);
    };

    let mat = delegation_material(d, parent.nonce);

    let mac1 = blake3::keyed_hash(key, &mat);
    let mut hasher2 = blake3::Hasher::new_keyed(key);
    hasher2.update(&mat);
    hasher2.update(b"DELEG");
    let mac2 = hasher2.finalize();

    if d.signature[..32] != *mac1.as_bytes() || d.signature[32..] != *mac2.as_bytes() {
        return Err(DelegationError::InvalidSignature);
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_test_token(owner: u64, caps: Vec<Capability>, nonce: u64) -> CapabilityToken {
        CapabilityToken {
            owner_module: owner,
            permissions: caps,
            expires_at_ms: None,
            nonce,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_delegation_display() {
        let d = Delegation {
            delegator: 1,
            delegatee: 2,
            capabilities: vec![Capability::IPC],
            expires_at_ms: Some(1000),
            parent_nonce: 123,
            signature: [0u8; 64],
        };
        let s = alloc::format!("{}", d);
        assert!(s.contains("1->2"));
        assert!(s.contains("caps:1"));
    }

    #[test]
    fn test_delegation_grants() {
        let d = Delegation {
            delegator: 1,
            delegatee: 2,
            capabilities: vec![Capability::IPC, Capability::Memory],
            expires_at_ms: None,
            parent_nonce: 1,
            signature: [0u8; 64],
        };

        assert!(d.grants(Capability::IPC));
        assert!(d.grants(Capability::Memory));
        assert!(!d.grants(Capability::Network));
    }

    #[test]
    fn test_delegation_error_display() {
        let e = DelegationError::CapabilityNotHeld;
        assert_eq!(e.as_str(), "Cannot delegate capability not held");

        let e = DelegationError::DelegationExpired;
        let s = alloc::format!("{}", e);
        assert!(s.contains("expired"));
    }

    #[test]
    fn test_delegation_expiry_check() {
        // No expiry
        let d = Delegation {
            delegator: 1,
            delegatee: 2,
            capabilities: vec![],
            expires_at_ms: None,
            parent_nonce: 1,
            signature: [0u8; 64],
        };
        assert!(!d.is_expired());
        assert!(d.is_valid());
        assert!(d.remaining_ms().is_none());

        // Future expiry
        let d = Delegation {
            delegator: 1,
            delegatee: 2,
            capabilities: vec![],
            expires_at_ms: Some(u64::MAX),
            parent_nonce: 1,
            signature: [0u8; 64],
        };
        assert!(!d.is_expired());
        assert!(d.remaining_ms().unwrap() > 0);
    }
}
