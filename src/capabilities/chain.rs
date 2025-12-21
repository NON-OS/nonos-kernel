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
//!
//! # Chain Structure
//! A valid chain links tokens where each delegation's delegatee becomes
//! the next token's owner

extern crate alloc;

use alloc::vec::Vec;

use super::{verify_token, Capability, CapabilityToken};

// ============================================================================
// Constants
// ============================================================================

/// Maximum chain depth (prevents infinite delegation chains)
const MAX_CHAIN_DEPTH: usize = 16;

// ============================================================================
// Chain Errors
// ============================================================================

/// Errors during chain verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// Chain has no tokens
    EmptyChain,
    /// Chain exceeds maximum depth
    TooDeep { depth: usize, max: usize },
    /// Token at index failed signature verification
    InvalidToken { index: usize },
    /// Token at index has expired
    ExpiredToken { index: usize },
    /// Link broken between tokens (delegatee != next owner)
    BrokenLink { index: usize },
    /// Capability not present in chain
    CapabilityNotFound,
}

impl ChainError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyChain => "Chain is empty",
            Self::TooDeep { .. } => "Chain exceeds maximum depth",
            Self::InvalidToken { .. } => "Token signature invalid",
            Self::ExpiredToken { .. } => "Token has expired",
            Self::BrokenLink { .. } => "Chain link broken",
            Self::CapabilityNotFound => "Capability not in chain",
        }
    }
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "Chain is empty"),
            Self::TooDeep { depth, max } => {
                write!(f, "Chain depth {} exceeds maximum {}", depth, max)
            }
            Self::InvalidToken { index } => {
                write!(f, "Token at index {} has invalid signature", index)
            }
            Self::ExpiredToken { index } => {
                write!(f, "Token at index {} has expired", index)
            }
            Self::BrokenLink { index } => {
                write!(f, "Chain link broken at index {}", index)
            }
            Self::CapabilityNotFound => write!(f, "Capability not found in chain"),
        }
    }
}

// ============================================================================
// Capability Chain
// ============================================================================

/// A chain of linked capability tokens
///
/// Represents a delegation chain where each token grants capabilities
/// to the owner of the next token in the chain.
#[derive(Debug, Clone)]
pub struct CapabilityChain {
    /// Ordered list of tokens (root first, leaf last)
    tokens: Vec<CapabilityToken>,
}

impl CapabilityChain {
    /// Create a new capability chain from tokens
    ///
    /// Tokens should be ordered from root (original grantor) to leaf (final grantee).
    pub fn new(tokens: Vec<CapabilityToken>) -> Self {
        Self { tokens }
    }

    /// Create an empty chain
    pub fn empty() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Create a single-token chain
    pub fn single(token: CapabilityToken) -> Self {
        Self {
            tokens: alloc::vec![token],
        }
    }

    /// Add a token to the end of the chain
    pub fn push(&mut self, token: CapabilityToken) {
        self.tokens.push(token);
    }

    /// Get chain length (number of tokens)
    #[inline]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if chain is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Get the root token (first in chain)
    pub fn root(&self) -> Option<&CapabilityToken> {
        self.tokens.first()
    }

    /// Get the leaf token (last in chain)
    pub fn leaf(&self) -> Option<&CapabilityToken> {
        self.tokens.last()
    }

    /// Get token at index
    pub fn get(&self, index: usize) -> Option<&CapabilityToken> {
        self.tokens.get(index)
    }

    /// Verify the entire chain
    ///
    /// Checks:
    /// 1. Chain is not empty
    /// 2. Chain does not exceed maximum depth
    /// 3. Each token has valid signature
    /// 4. Each token has not expired
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Chain is valid
    /// * `Err(ChainError)` - Verification failed with reason
    pub fn verify(&self) -> Result<(), ChainError> {
        // Check empty
        if self.tokens.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        // Check depth
        if self.tokens.len() > MAX_CHAIN_DEPTH {
            return Err(ChainError::TooDeep {
                depth: self.tokens.len(),
                max: MAX_CHAIN_DEPTH,
            });
        }

        // Verify each token
        for (i, token) in self.tokens.iter().enumerate() {
            // Check signature
            if !verify_token(token) {
                return Err(ChainError::InvalidToken { index: i });
            }

            // Check expiry
            if !token.not_expired() {
                return Err(ChainError::ExpiredToken { index: i });
            }
        }

        Ok(())
    }

    /// Verify chain and check that a specific capability is granted
    ///
    /// The capability must be present in ALL tokens in the chain
    /// (capabilities can only be delegated if the delegator has them).
    pub fn verify_capability(&self, cap: Capability) -> Result<(), ChainError> {
        self.verify()?;

        // Check capability exists in all tokens
        for token in &self.tokens {
            if !token.grants(cap) {
                return Err(ChainError::CapabilityNotFound);
            }
        }

        Ok(())
    }

    /// Get the intersection of capabilities across all tokens
    ///
    /// Returns capabilities that are present in every token in the chain.
    pub fn effective_capabilities(&self) -> Vec<Capability> {
        if self.tokens.is_empty() {
            return Vec::new();
        }

        // Start with first token's capabilities
        let mut caps: Vec<Capability> = self.tokens[0].permissions.clone();

        // Intersect with each subsequent token
        for token in self.tokens.iter().skip(1) {
            caps.retain(|c| token.grants(*c));
        }

        caps
    }

    /// Get the final owner (leaf token's owner)
    pub fn final_owner(&self) -> Option<u64> {
        self.leaf().map(|t| t.owner_module)
    }

    /// Get the root owner (first token's owner)
    pub fn root_owner(&self) -> Option<u64> {
        self.root().map(|t| t.owner_module)
    }

    /// Check if chain is valid (convenience method)
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.verify().is_ok()
    }

    /// Get maximum allowed chain depth
    #[inline]
    pub const fn max_depth() -> usize {
        MAX_CHAIN_DEPTH
    }
}

impl core::fmt::Display for CapabilityChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Chain[len:{}", self.tokens.len())?;
        if let Some(root) = self.root_owner() {
            write!(f, " root:{}", root)?;
        }
        if let Some(leaf) = self.final_owner() {
            write!(f, " leaf:{}", leaf)?;
        }
        write!(f, " caps:{}", self.effective_capabilities().len())?;
        write!(f, "]")
    }
}

impl Default for CapabilityChain {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_test_token(owner: u64, caps: Vec<Capability>) -> CapabilityToken {
        CapabilityToken {
            owner_module: owner,
            permissions: caps,
            expires_at_ms: None,
            nonce: 1,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_empty_chain() {
        let chain = CapabilityChain::empty();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.root().is_none());
        assert!(chain.leaf().is_none());
    }

    #[test]
    fn test_single_token_chain() {
        let token = make_test_token(42, vec![Capability::IPC]);
        let chain = CapabilityChain::single(token);

        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.root_owner(), Some(42));
        assert_eq!(chain.final_owner(), Some(42));
    }

    #[test]
    fn test_chain_display() {
        let chain = CapabilityChain::new(vec![
            make_test_token(1, vec![Capability::IPC, Capability::Memory]),
            make_test_token(2, vec![Capability::IPC]),
        ]);
        let s = alloc::format!("{}", chain);
        assert!(s.contains("len:2"));
        assert!(s.contains("root:1"));
        assert!(s.contains("leaf:2"));
    }

    #[test]
    fn test_effective_capabilities() {
        let chain = CapabilityChain::new(vec![
            make_test_token(1, vec![Capability::IPC, Capability::Memory, Capability::IO]),
            make_test_token(2, vec![Capability::IPC, Capability::Memory]),
            make_test_token(3, vec![Capability::IPC]),
        ]);

        let caps = chain.effective_capabilities();
        assert_eq!(caps.len(), 1);
        assert!(caps.contains(&Capability::IPC));
    }

    #[test]
    fn test_chain_error_display() {
        let e = ChainError::InvalidToken { index: 2 };
        assert!(alloc::format!("{}", e).contains("index 2"));

        let e = ChainError::TooDeep { depth: 20, max: 16 };
        assert!(alloc::format!("{}", e).contains("20"));
    }

    #[test]
    fn test_max_depth() {
        assert_eq!(CapabilityChain::max_depth(), MAX_CHAIN_DEPTH);
    }
}
