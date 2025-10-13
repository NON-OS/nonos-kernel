#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use crate::capabilities::{CapabilityToken, verify_token};

#[derive(Debug, Clone)]
pub struct CapabilityChain {
    pub tokens: Vec<CapabilityToken>,
}

impl CapabilityChain {
    pub fn new(tokens: Vec<CapabilityToken>) -> Self {
        Self { tokens }
    }

    /// Verify the whole chain: each token valid and the chain of owners matches.
    pub fn verify_chain(&self) -> bool {
        if self.tokens.is_empty() { return false; }
        let mut last_owner = self.tokens[0].owner_module;
        for tok in &self.tokens {
            if !verify_token(tok) { return false; }
            if tok.owner_module != last_owner { return false; } // owner should be consistent
            last_owner = tok.owner_module;
        }
        true
    }
}
