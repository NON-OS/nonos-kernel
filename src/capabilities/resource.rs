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
//! Cryptographically signed tokens that grant resource usage quotas.
//! Used to limit memory, I/O operations, and other system resources.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use super::signing_key;

// ============================================================================
// Errors
// ============================================================================

/// Resource token operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// Signing key not available
    MissingSigningKey,
    /// Token has expired
    TokenExpired,
    /// Signature verification failed
    InvalidSignature,
    /// Insufficient bytes remaining
    InsufficientBytes { requested: u64, available: u64 },
    /// Insufficient operations remaining
    InsufficientOps { requested: u64, available: u64 },
    /// Zero quota not allowed
    ZeroQuota,
}

impl ResourceError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingSigningKey => "Signing key not available",
            Self::TokenExpired => "Token has expired",
            Self::InvalidSignature => "Signature verification failed",
            Self::InsufficientBytes { .. } => "Insufficient bytes",
            Self::InsufficientOps { .. } => "Insufficient operations",
            Self::ZeroQuota => "Zero quota not allowed",
        }
    }
}

impl core::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingSigningKey => write!(f, "Signing key not available"),
            Self::TokenExpired => write!(f, "Token has expired"),
            Self::InvalidSignature => write!(f, "Signature verification failed"),
            Self::InsufficientBytes {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient bytes: requested {}, available {}",
                    requested, available
                )
            }
            Self::InsufficientOps {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient ops: requested {}, available {}",
                    requested, available
                )
            }
            Self::ZeroQuota => write!(f, "Zero quota not allowed"),
        }
    }
}

// ============================================================================
// Resource Quota
// ============================================================================

/// Resource quota limits
#[derive(Debug, Clone, Copy)]
pub struct ResourceQuota {
    /// Maximum bytes allowed
    pub bytes: u64,
    /// Maximum operations allowed
    pub ops: u64,
    /// Expiration timestamp (ms since boot)
    pub expires_at_ms: Option<u64>,
}

impl ResourceQuota {
    /// Create a new resource quota
    ///
    /// # Arguments
    ///
    /// * `bytes` - Maximum bytes allowed
    /// * `ops` - Maximum operations allowed
    /// * `expires_at_ms` - Optional expiration timestamp
    pub const fn new(bytes: u64, ops: u64, expires_at_ms: Option<u64>) -> Self {
        Self {
            bytes,
            ops,
            expires_at_ms,
        }
    }

    /// Create unlimited quota (no expiry)
    pub const fn unlimited() -> Self {
        Self {
            bytes: u64::MAX,
            ops: u64::MAX,
            expires_at_ms: None,
        }
    }

    /// Check if quota has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() >= exp,
            None => false,
        }
    }

    /// Check if quota is empty (no bytes or ops)
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes == 0 && self.ops == 0
    }
}

impl core::fmt::Display for ResourceQuota {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Quota[{}B {}ops", self.bytes, self.ops)?;
        if let Some(exp) = self.expires_at_ms {
            write!(f, " exp:{}ms", exp)?;
        }
        write!(f, "]")
    }
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self::new(0, 0, None)
    }
}

// ============================================================================
// Resource Token
// ============================================================================

/// Nonce counter for token uniqueness
static NONCE_CTR: AtomicU64 = AtomicU64::new(1);

/// Generate a unique nonce
fn next_nonce() -> u64 {
    let t = crate::time::timestamp_millis();
    let c = NONCE_CTR.fetch_add(1, Ordering::Relaxed) & 0xFFFF_FFFF;
    (t << 32) ^ c
}

/// A signed resource quota token
///
/// Tracks remaining quota and provides consumption API.
#[derive(Debug, Clone)]
pub struct ResourceToken {
    /// Owner module ID
    pub owner_module: u64,
    /// Original quota (for reference)
    original_quota: ResourceQuota,
    /// Remaining bytes
    remaining_bytes: u64,
    /// Remaining operations
    remaining_ops: u64,
    /// Unique nonce
    pub nonce: u64,
    /// Cryptographic signature
    pub signature: [u8; 64],
}

impl ResourceToken {
    /// Get original quota
    #[inline]
    pub fn original_quota(&self) -> &ResourceQuota {
        &self.original_quota
    }

    /// Get remaining bytes
    #[inline]
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }

    /// Get remaining operations
    #[inline]
    pub fn remaining_ops(&self) -> u64 {
        self.remaining_ops
    }

    /// Get bytes used
    #[inline]
    pub fn bytes_used(&self) -> u64 {
        self.original_quota.bytes.saturating_sub(self.remaining_bytes)
    }

    /// Get operations used
    #[inline]
    pub fn ops_used(&self) -> u64 {
        self.original_quota.ops.saturating_sub(self.remaining_ops)
    }

    /// Get byte usage percentage (0-100)
    pub fn bytes_usage_percent(&self) -> f64 {
        if self.original_quota.bytes == 0 {
            return 0.0;
        }
        (self.bytes_used() as f64 / self.original_quota.bytes as f64) * 100.0
    }

    /// Get ops usage percentage (0-100)
    pub fn ops_usage_percent(&self) -> f64 {
        if self.original_quota.ops == 0 {
            return 0.0;
        }
        (self.ops_used() as f64 / self.original_quota.ops as f64) * 100.0
    }

    /// Check if token has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.original_quota.is_expired()
    }

    /// Check if quota is exhausted
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.remaining_bytes == 0 && self.remaining_ops == 0
    }

    /// Check if enough bytes are available
    #[inline]
    pub fn has_bytes(&self, amount: u64) -> bool {
        self.remaining_bytes >= amount
    }

    /// Check if enough ops are available
    #[inline]
    pub fn has_ops(&self, count: u64) -> bool {
        self.remaining_ops >= count
    }

    /// Try to consume bytes (internal, no signature check)
    fn consume_bytes(&mut self, amount: u64) -> Result<(), ResourceError> {
        if self.remaining_bytes < amount {
            return Err(ResourceError::InsufficientBytes {
                requested: amount,
                available: self.remaining_bytes,
            });
        }
        self.remaining_bytes -= amount;
        Ok(())
    }

    /// Try to consume ops (internal, no signature check)
    fn consume_ops(&mut self, count: u64) -> Result<(), ResourceError> {
        if self.remaining_ops < count {
            return Err(ResourceError::InsufficientOps {
                requested: count,
                available: self.remaining_ops,
            });
        }
        self.remaining_ops -= count;
        Ok(())
    }
}

impl core::fmt::Display for ResourceToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ResourceToken[owner:{} bytes:{}/{} ops:{}/{}]",
            self.owner_module,
            self.remaining_bytes,
            self.original_quota.bytes,
            self.remaining_ops,
            self.original_quota.ops
        )
    }
}

// ============================================================================
// Token Operations
// ============================================================================

/// Compute signature material
fn token_material(owner: u64, quota: &ResourceQuota, nonce: u64) -> [u8; 40] {
    let mut mat = [0u8; 40];
    mat[0..8].copy_from_slice(&owner.to_le_bytes());
    mat[8..16].copy_from_slice(&quota.bytes.to_le_bytes());
    mat[16..24].copy_from_slice(&quota.ops.to_le_bytes());
    mat[24..32].copy_from_slice(&quota.expires_at_ms.unwrap_or(0).to_le_bytes());
    mat[32..40].copy_from_slice(&nonce.to_le_bytes());
    mat
}

/// Create a new signed resource token
///
/// # Arguments
///
/// * `owner` - Owner module ID
/// * `quota` - Resource quota to grant
///
/// # Returns
///
/// * `Ok(ResourceToken)` - Signed token
/// * `Err(ResourceError)` - Creation failed
pub fn create_resource_token(owner: u64, quota: ResourceQuota) -> Result<ResourceToken, ResourceError> {
    // Validate quota
    if quota.is_empty() {
        return Err(ResourceError::ZeroQuota);
    }

    let nonce = next_nonce();
    let mut token = ResourceToken {
        owner_module: owner,
        original_quota: quota,
        remaining_bytes: quota.bytes,
        remaining_ops: quota.ops,
        nonce,
        signature: [0u8; 64],
    };

    sign_resource_token(&mut token)?;
    Ok(token)
}

/// Sign a resource token
pub fn sign_resource_token(tok: &mut ResourceToken) -> Result<(), ResourceError> {
    let key = signing_key().ok_or(ResourceError::MissingSigningKey)?;

    let mat = token_material(tok.owner_module, &tok.original_quota, tok.nonce);

    // Dual MAC for 64-byte signature
    let mac1 = blake3::keyed_hash(key, &mat);
    let mut hasher2 = blake3::Hasher::new_keyed(key);
    hasher2.update(&mat);
    hasher2.update(b"RSRC");
    let mac2 = hasher2.finalize();

    tok.signature[..32].copy_from_slice(mac1.as_bytes());
    tok.signature[32..].copy_from_slice(mac2.as_bytes());

    Ok(())
}

/// Verify a resource token's signature
pub fn verify_resource_token(tok: &ResourceToken) -> bool {
    let Some(key) = signing_key() else {
        return false;
    };

    let mat = token_material(tok.owner_module, &tok.original_quota, tok.nonce);

    let mac1 = blake3::keyed_hash(key, &mat);
    let mut hasher2 = blake3::Hasher::new_keyed(key);
    hasher2.update(&mat);
    hasher2.update(b"RSRC");
    let mac2 = hasher2.finalize();

    tok.signature[..32] == *mac1.as_bytes() && tok.signature[32..] == *mac2.as_bytes()
}

/// Strict verification with detailed error
pub fn verify_resource_token_strict(tok: &ResourceToken) -> Result<(), ResourceError> {
    if tok.is_expired() {
        return Err(ResourceError::TokenExpired);
    }

    let Some(key) = signing_key() else {
        return Err(ResourceError::MissingSigningKey);
    };

    let mat = token_material(tok.owner_module, &tok.original_quota, tok.nonce);

    let mac1 = blake3::keyed_hash(key, &mat);
    let mut hasher2 = blake3::Hasher::new_keyed(key);
    hasher2.update(&mat);
    hasher2.update(b"RSRC");
    let mac2 = hasher2.finalize();

    if tok.signature[..32] != *mac1.as_bytes() || tok.signature[32..] != *mac2.as_bytes() {
        return Err(ResourceError::InvalidSignature);
    }

    Ok(())
}

/// Try to consume resources from a token
///
/// # Arguments
///
/// * `token` - Token to consume from
/// * `bytes` - Number of bytes to consume
/// * `ops` - Number of operations to consume
///
/// # Returns
///
/// * `Ok(())` - Resources consumed
/// * `Err(ResourceError)` - Insufficient resources or token invalid
pub fn try_consume(token: &mut ResourceToken, bytes: u64, ops: u64) -> Result<(), ResourceError> {
    // Check expiry
    if token.is_expired() {
        return Err(ResourceError::TokenExpired);
    }

    // Check availability before consuming
    if !token.has_bytes(bytes) {
        return Err(ResourceError::InsufficientBytes {
            requested: bytes,
            available: token.remaining_bytes,
        });
    }

    if !token.has_ops(ops) {
        return Err(ResourceError::InsufficientOps {
            requested: ops,
            available: token.remaining_ops,
        });
    }

    // Consume atomically (both or neither)
    token.consume_bytes(bytes)?;
    token.consume_ops(ops)?;

    Ok(())
}

/// Reset token to original quota (re-signs)
pub fn reset_token(token: &mut ResourceToken) -> Result<(), ResourceError> {
    token.remaining_bytes = token.original_quota.bytes;
    token.remaining_ops = token.original_quota.ops;
    token.nonce = next_nonce();
    sign_resource_token(token)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_display() {
        let q = ResourceQuota::new(1024, 100, Some(5000));
        let s = alloc::format!("{}", q);
        assert!(s.contains("1024B"));
        assert!(s.contains("100ops"));
        assert!(s.contains("5000ms"));
    }

    #[test]
    fn test_quota_unlimited() {
        let q = ResourceQuota::unlimited();
        assert_eq!(q.bytes, u64::MAX);
        assert_eq!(q.ops, u64::MAX);
        assert!(q.expires_at_ms.is_none());
    }

    #[test]
    fn test_token_display() {
        let quota = ResourceQuota::new(1000, 50, None);
        let token = ResourceToken {
            owner_module: 42,
            original_quota: quota,
            remaining_bytes: 500,
            remaining_ops: 25,
            nonce: 1,
            signature: [0u8; 64],
        };
        let s = alloc::format!("{}", token);
        assert!(s.contains("owner:42"));
        assert!(s.contains("500/1000"));
        assert!(s.contains("25/50"));
    }

    #[test]
    fn test_token_usage_tracking() {
        let quota = ResourceQuota::new(1000, 100, None);
        let mut token = ResourceToken {
            owner_module: 1,
            original_quota: quota,
            remaining_bytes: 1000,
            remaining_ops: 100,
            nonce: 1,
            signature: [0u8; 64],
        };

        assert_eq!(token.bytes_used(), 0);
        assert_eq!(token.ops_used(), 0);

        token.remaining_bytes = 600;
        token.remaining_ops = 40;

        assert_eq!(token.bytes_used(), 400);
        assert_eq!(token.ops_used(), 60);
        assert!((token.bytes_usage_percent() - 40.0).abs() < 0.01);
        assert!((token.ops_usage_percent() - 60.0).abs() < 0.01);
    }

    #[test]
    fn test_consume_validation() {
        let quota = ResourceQuota::new(100, 10, None);
        let mut token = ResourceToken {
            owner_module: 1,
            original_quota: quota,
            remaining_bytes: 100,
            remaining_ops: 10,
            nonce: 1,
            signature: [0u8; 64],
        };

        // Consume some
        assert!(token.consume_bytes(50).is_ok());
        assert_eq!(token.remaining_bytes, 50);

        // Try to over-consume
        let result = token.consume_bytes(100);
        assert!(matches!(result, Err(ResourceError::InsufficientBytes { .. })));

        // Ops
        assert!(token.consume_ops(5).is_ok());
        let result = token.consume_ops(10);
        assert!(matches!(result, Err(ResourceError::InsufficientOps { .. })));
    }

    #[test]
    fn test_error_display() {
        let e = ResourceError::InsufficientBytes {
            requested: 100,
            available: 50,
        };
        let s = alloc::format!("{}", e);
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn test_is_exhausted() {
        let quota = ResourceQuota::new(100, 10, None);
        let mut token = ResourceToken {
            owner_module: 1,
            original_quota: quota,
            remaining_bytes: 100,
            remaining_ops: 10,
            nonce: 1,
            signature: [0u8; 64],
        };

        assert!(!token.is_exhausted());
        token.remaining_bytes = 0;
        assert!(!token.is_exhausted());
        token.remaining_ops = 0;
        assert!(token.is_exhausted());
    }
}
