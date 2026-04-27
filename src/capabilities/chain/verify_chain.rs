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

use crate::capabilities::token::verify_token;

use super::chain::CapabilityChain;
use super::constants::MAX_CHAIN_DEPTH;
use super::error::ChainError;

pub fn verify_chain(chain: &CapabilityChain) -> Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(ChainError::TooDeep { depth: chain.len(), max: MAX_CHAIN_DEPTH });
    }
    for (i, token) in chain.tokens.iter().enumerate() {
        if !verify_token(token) {
            return Err(ChainError::InvalidToken { index: i });
        }
        if !token.not_expired() {
            return Err(ChainError::ExpiredToken { index: i });
        }
    }
    Ok(())
}

pub fn first_invalid_index(chain: &CapabilityChain) -> Option<usize> {
    for (i, token) in chain.tokens.iter().enumerate() {
        if !verify_token(token) || !token.not_expired() {
            return Some(i);
        }
    }
    None
}

pub fn is_chain_valid(chain: &CapabilityChain) -> bool {
    verify_chain(chain).is_ok()
}
