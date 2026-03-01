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

extern crate alloc;

use alloc::vec::Vec;

use crate::capabilities::token::CapabilityToken;

use super::constants::MAX_CHAIN_DEPTH;

#[derive(Debug, Clone)]
pub struct CapabilityChain {
    pub(super) tokens: Vec<CapabilityToken>,
}

impl CapabilityChain {
    pub fn new(tokens: Vec<CapabilityToken>) -> Self {
        Self { tokens }
    }

    pub fn empty() -> Self {
        Self { tokens: Vec::new() }
    }

    pub fn single(token: CapabilityToken) -> Self {
        Self {
            tokens: alloc::vec![token],
        }
    }

    pub fn push(&mut self, token: CapabilityToken) {
        self.tokens.push(token);
    }

    pub fn pop(&mut self) -> Option<CapabilityToken> {
        self.tokens.pop()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    pub fn root(&self) -> Option<&CapabilityToken> {
        self.tokens.first()
    }

    pub fn leaf(&self) -> Option<&CapabilityToken> {
        self.tokens.last()
    }

    pub fn get(&self, index: usize) -> Option<&CapabilityToken> {
        self.tokens.get(index)
    }

    pub fn tokens(&self) -> &[CapabilityToken] {
        &self.tokens
    }

    pub fn final_owner(&self) -> Option<u64> {
        self.leaf().map(|t| t.owner_module)
    }

    pub fn root_owner(&self) -> Option<u64> {
        self.root().map(|t| t.owner_module)
    }

    #[inline]
    pub const fn max_depth() -> usize {
        MAX_CHAIN_DEPTH
    }
}

impl Default for CapabilityChain {
    fn default() -> Self {
        Self::empty()
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
        write!(f, "]")
    }
}
