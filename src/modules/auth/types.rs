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

use super::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    None,
    Ed25519,
    Dilithium,
    Hybrid,
    TrustedKeys,
    VaultSignature,
}

impl Default for AuthMethod {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl AuthMethod {
    pub const fn requires_pqc(&self) -> bool {
        matches!(self, Self::Dilithium | Self::Hybrid)
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Ed25519 => "Ed25519",
            Self::Dilithium => "Dilithium",
            Self::Hybrid => "Hybrid",
            Self::TrustedKeys => "TrustedKeys",
            Self::VaultSignature => "VaultSignature",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub verified: bool,
    pub pqc_verified: bool,
    pub attestation_valid: bool,
    pub method: AuthMethod,
    pub hash: [u8; BLAKE3_HASH_SIZE],
}

impl Default for AuthContext {
    fn default() -> Self {
        Self {
            verified: false,
            pqc_verified: false,
            attestation_valid: false,
            method: AuthMethod::default(),
            hash: [0u8; BLAKE3_HASH_SIZE],
        }
    }
}

impl AuthContext {
    pub const fn new() -> Self {
        Self {
            verified: false,
            pqc_verified: false,
            attestation_valid: false,
            method: AuthMethod::Ed25519,
            hash: [0u8; BLAKE3_HASH_SIZE],
        }
    }

    pub fn with_hash(mut self, hash: [u8; BLAKE3_HASH_SIZE]) -> Self {
        self.hash = hash;
        self
    }

    pub fn with_method(mut self, method: AuthMethod) -> Self {
        self.method = method;
        self
    }

    pub const fn is_verified(&self) -> bool {
        self.verified || self.pqc_verified
    }

    pub const fn is_fully_verified(&self) -> bool {
        self.verified && self.pqc_verified && self.attestation_valid
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureData {
    pub signature: [u8; ED25519_SIGNATURE_SIZE],
    pub pubkey: [u8; ED25519_PUBKEY_SIZE],
}

impl SignatureData {
    pub const fn new(signature: [u8; ED25519_SIGNATURE_SIZE], pubkey: [u8; ED25519_PUBKEY_SIZE]) -> Self {
        Self { signature, pubkey }
    }

    pub fn r(&self) -> &[u8; 32] {
        // SAFETY: Signature is 64 bytes, first 32 are R
        unsafe { &*(self.signature[..32].as_ptr() as *const [u8; 32]) }
    }

    pub fn s(&self) -> &[u8; 32] {
        // SAFETY: Signature is 64 bytes, last 32 are S
        unsafe { &*(self.signature[32..].as_ptr() as *const [u8; 32]) }
    }
}
