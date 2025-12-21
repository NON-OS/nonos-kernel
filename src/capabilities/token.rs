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
//! Capability Token Implementation
//!
//! Core token type with signing, verification, and serialization.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Once, RwLock};

use super::{bits_to_caps, caps_to_bits, Capability};

// ============================================================================
// Capability Token
// ============================================================================

/// Cryptographically signed capability token
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    /// Issuer/subject module ID
    pub owner_module: u64,
    /// Granted capabilities
    pub permissions: Vec<Capability>,
    /// Expiration timestamp (ms since boot), None = no expiry
    pub expires_at_ms: Option<u64>,
    /// Unique nonce for anti-replay
    pub nonce: u64,
    /// Dual MAC signature
    pub signature: [u8; 64],
}

impl CapabilityToken {
    /// Check if token grants a specific capability
    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.permissions.iter().any(|c| *c == cap)
    }

    /// Check if token has not expired
    #[inline]
    pub fn not_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() < exp,
            None => true,
        }
    }

    /// Get remaining time until expiry
    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms.map(|exp| {
            exp.saturating_sub(crate::time::timestamp_millis())
        })
    }

    /// Full validity check
    pub fn is_valid(&self) -> bool {
        verify_token(self) && self.not_expired() && !is_revoked(self.owner_module, self.nonce)
    }

    /// Serialize to binary: [ver:1][owner:8][bits:8][exp:8][nonce:8][sig:64]
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        out[0] = 1; // version
        out[1..9].copy_from_slice(&self.owner_module.to_le_bytes());
        out[9..17].copy_from_slice(&caps_to_bits(&self.permissions).to_le_bytes());
        out[17..25].copy_from_slice(&self.expires_at_ms.unwrap_or(0).to_le_bytes());
        out[25..33].copy_from_slice(&self.nonce.to_le_bytes());
        out[33..97].copy_from_slice(&self.signature);
        out
    }

    /// Deserialize from binary
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != 97 { return Err("Invalid size"); }
        if buf[0] != 1 { return Err("Invalid version"); }

        let owner = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let bits = u64::from_le_bytes(buf[9..17].try_into().unwrap());
        let exp = u64::from_le_bytes(buf[17..25].try_into().unwrap());
        let nonce = u64::from_le_bytes(buf[25..33].try_into().unwrap());
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&buf[33..97]);

        Ok(Self {
            owner_module: owner,
            permissions: bits_to_caps(bits),
            expires_at_ms: if exp == 0 { None } else { Some(exp) },
            nonce,
            signature: sig,
        })
    }
}

impl core::fmt::Display for CapabilityToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Token[owner:{} caps:{} nonce:{:016x}]",
            self.owner_module, self.permissions.len(), self.nonce)
    }
}

// ============================================================================
// Signing Key
// ============================================================================

static SIGNING_KEY: Once<[u8; 32]> = Once::new();

/// Install signing key (once during boot)
pub fn set_signing_key(key: &[u8]) -> Result<(), &'static str> {
    if key.len() != 32 { return Err("Key must be 32 bytes"); }
    if SIGNING_KEY.get().is_some() { return Err("Key already set"); }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(key);
    SIGNING_KEY.call_once(|| arr);
    Ok(())
}

#[inline]
pub fn has_signing_key() -> bool { SIGNING_KEY.get().is_some() }

#[inline]
pub fn signing_key() -> Option<&'static [u8; 32]> { SIGNING_KEY.get() }

// ============================================================================
// Signature Operations
// ============================================================================

fn token_material(owner: u64, bits: u64, exp: u64, nonce: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&owner.to_le_bytes());
    out[8..16].copy_from_slice(&bits.to_le_bytes());
    out[16..24].copy_from_slice(&exp.to_le_bytes());
    out[24..32].copy_from_slice(&nonce.to_le_bytes());
    out
}

fn mac64(key: &[u8; 32], mat: &[u8]) -> [u8; 64] {
    let mac1 = blake3::keyed_hash(key, mat);
    let mut ctx2 = blake3::Hasher::new_keyed(key);
    ctx2.update(mat);
    ctx2.update(b"CAP2");
    let mac2 = ctx2.finalize();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(mac1.as_bytes());
    out[32..].copy_from_slice(mac2.as_bytes());
    out
}

/// Sign a token in-place
pub fn sign_token(tok: &mut CapabilityToken) -> Result<(), &'static str> {
    let key = signing_key().ok_or("No signing key")?;
    if tok.nonce == 0 { tok.nonce = default_nonce(); }

    let mat = token_material(
        tok.owner_module,
        caps_to_bits(&tok.permissions),
        tok.expires_at_ms.unwrap_or(0),
        tok.nonce,
    );
    tok.signature = mac64(key, &mat);
    Ok(())
}

/// Verify token signature
pub fn verify_token(tok: &CapabilityToken) -> bool {
    let Some(key) = signing_key() else { return false; };

    let mat = token_material(
        tok.owner_module,
        caps_to_bits(&tok.permissions),
        tok.expires_at_ms.unwrap_or(0),
        tok.nonce,
    );
    mac64(key, &mat) == tok.signature
}

// ============================================================================
// Nonce & Creation
// ============================================================================

static NONCE_CTR: AtomicU64 = AtomicU64::new(1);

#[inline]
pub fn default_nonce() -> u64 {
    let t = crate::time::timestamp_millis();
    let c = NONCE_CTR.fetch_add(1, Ordering::Relaxed) & 0xFFFF_FFFF;
    (t << 32) ^ c
}

/// Create and sign a new token
pub fn create_token(
    owner: u64,
    caps: &[Capability],
    ttl_ms: Option<u64>,
) -> Result<CapabilityToken, &'static str> {
    let exp = ttl_ms.map(|t| crate::time::timestamp_millis().saturating_add(t));
    let mut tok = CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: exp,
        nonce: 0,
        signature: [0u8; 64],
    };
    sign_token(&mut tok)?;
    Ok(tok)
}

// ============================================================================
// Revocation
// ============================================================================

static REVOKED: RwLock<BTreeSet<(u64, u64)>> = RwLock::new(BTreeSet::new());

pub fn revoke_token(owner: u64, nonce: u64) {
    REVOKED.write().insert((owner, nonce));
}

#[inline]
pub fn is_revoked(owner: u64, nonce: u64) -> bool {
    REVOKED.read().contains(&(owner, nonce))
}

#[inline]
pub fn revoked_count() -> usize { REVOKED.read().len() }

pub fn clear_revocations() { REVOKED.write().clear(); }
