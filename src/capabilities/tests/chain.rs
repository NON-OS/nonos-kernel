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

use crate::capabilities::*;

fn make_token(owner: u64, caps: &[Capability]) -> CapabilityToken {
    CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    }
}

#[test]
fn test_capability_chain_new() {
    let tokens = alloc::vec![make_token(1, &[Capability::Admin])];
    let chain = CapabilityChain::new(tokens);
    assert_eq!(chain.len(), 1);
}

#[test]
fn test_capability_chain_empty() {
    let chain = CapabilityChain::empty();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
}

#[test]
fn test_capability_chain_single() {
    let tok = make_token(42, &[Capability::Admin]);
    let chain = CapabilityChain::single(tok);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
}

#[test]
fn test_capability_chain_push() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    assert_eq!(chain.len(), 2);
}

#[test]
fn test_capability_chain_pop() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let popped = chain.pop();
    assert!(popped.is_some());
    assert_eq!(popped.unwrap().owner_module, 2);
    assert_eq!(chain.len(), 1);
}

#[test]
fn test_capability_chain_pop_empty() {
    let mut chain = CapabilityChain::empty();
    assert!(chain.pop().is_none());
}

#[test]
fn test_capability_chain_root() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let root = chain.root().unwrap();
    assert_eq!(root.owner_module, 1);
}

#[test]
fn test_capability_chain_root_empty() {
    let chain = CapabilityChain::empty();
    assert!(chain.root().is_none());
}

#[test]
fn test_capability_chain_leaf() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let leaf = chain.leaf().unwrap();
    assert_eq!(leaf.owner_module, 2);
}

#[test]
fn test_capability_chain_leaf_empty() {
    let chain = CapabilityChain::empty();
    assert!(chain.leaf().is_none());
}

#[test]
fn test_capability_chain_get() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    assert_eq!(chain.get(0).unwrap().owner_module, 1);
    assert_eq!(chain.get(1).unwrap().owner_module, 2);
    assert!(chain.get(2).is_none());
}

#[test]
fn test_capability_chain_tokens() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let tokens = chain.tokens();
    assert_eq!(tokens.len(), 2);
}

#[test]
fn test_capability_chain_final_owner() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(99, &[Capability::Debug]));
    assert_eq!(chain.final_owner(), Some(99));
}

#[test]
fn test_capability_chain_final_owner_empty() {
    let chain = CapabilityChain::empty();
    assert!(chain.final_owner().is_none());
}

#[test]
fn test_capability_chain_root_owner() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(42, &[Capability::Admin]));
    chain.push(make_token(99, &[Capability::Debug]));
    assert_eq!(chain.root_owner(), Some(42));
}

#[test]
fn test_capability_chain_root_owner_empty() {
    let chain = CapabilityChain::empty();
    assert!(chain.root_owner().is_none());
}

#[test]
fn test_capability_chain_max_depth() {
    assert_eq!(CapabilityChain::max_depth(), MAX_CHAIN_DEPTH);
}

#[test]
fn test_capability_chain_default() {
    let chain = CapabilityChain::default();
    assert!(chain.is_empty());
}

#[test]
fn test_capability_chain_display() {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(10, &[Capability::Admin]));
    chain.push(make_token(20, &[Capability::Debug]));
    let display = alloc::format!("{}", chain);
    assert!(display.contains("len:2"));
    assert!(display.contains("root:10"));
    assert!(display.contains("leaf:20"));
}

#[test]
fn test_max_chain_depth_constant() {
    assert_eq!(MAX_CHAIN_DEPTH, 16);
}

#[test]
fn test_max_chain_depth_function() {
    assert_eq!(max_chain_depth(), 16);
}

#[test]
fn test_chain_error_empty_chain_as_str() {
    let err = ChainError::EmptyChain;
    assert_eq!(err.as_str(), "Chain is empty");
}

#[test]
fn test_chain_error_too_deep_as_str() {
    let err = ChainError::TooDeep { depth: 20, max: 16 };
    assert_eq!(err.as_str(), "Chain exceeds maximum depth");
}

#[test]
fn test_chain_error_invalid_token_as_str() {
    let err = ChainError::InvalidToken { index: 5 };
    assert_eq!(err.as_str(), "Token signature invalid");
}

#[test]
fn test_chain_error_expired_token_as_str() {
    let err = ChainError::ExpiredToken { index: 3 };
    assert_eq!(err.as_str(), "Token has expired");
}

#[test]
fn test_chain_error_broken_link_as_str() {
    let err = ChainError::BrokenLink { index: 2 };
    assert_eq!(err.as_str(), "Chain link broken");
}

#[test]
fn test_chain_error_capability_not_found_as_str() {
    let err = ChainError::CapabilityNotFound;
    assert_eq!(err.as_str(), "Capability not in chain");
}

#[test]
fn test_chain_error_is_recoverable_expired() {
    let err = ChainError::ExpiredToken { index: 0 };
    assert!(err.is_recoverable());
}

#[test]
fn test_chain_error_is_recoverable_cap_not_found() {
    let err = ChainError::CapabilityNotFound;
    assert!(err.is_recoverable());
}

#[test]
fn test_chain_error_is_recoverable_empty() {
    let err = ChainError::EmptyChain;
    assert!(!err.is_recoverable());
}

#[test]
fn test_chain_error_is_recoverable_invalid() {
    let err = ChainError::InvalidToken { index: 0 };
    assert!(!err.is_recoverable());
}

#[test]
fn test_chain_error_failed_index_invalid_token() {
    let err = ChainError::InvalidToken { index: 5 };
    assert_eq!(err.failed_index(), Some(5));
}

#[test]
fn test_chain_error_failed_index_expired_token() {
    let err = ChainError::ExpiredToken { index: 3 };
    assert_eq!(err.failed_index(), Some(3));
}

#[test]
fn test_chain_error_failed_index_broken_link() {
    let err = ChainError::BrokenLink { index: 7 };
    assert_eq!(err.failed_index(), Some(7));
}

#[test]
fn test_chain_error_failed_index_empty_chain() {
    let err = ChainError::EmptyChain;
    assert!(err.failed_index().is_none());
}

#[test]
fn test_chain_error_failed_index_cap_not_found() {
    let err = ChainError::CapabilityNotFound;
    assert!(err.failed_index().is_none());
}

#[test]
fn test_chain_error_display_empty_chain() {
    let err = ChainError::EmptyChain;
    let display = alloc::format!("{}", err);
    assert!(display.contains("empty"));
}

#[test]
fn test_chain_error_display_too_deep() {
    let err = ChainError::TooDeep { depth: 20, max: 16 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("20"));
    assert!(display.contains("16"));
}

#[test]
fn test_chain_error_display_invalid_token() {
    let err = ChainError::InvalidToken { index: 5 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("5"));
    assert!(display.contains("invalid"));
}

#[test]
fn test_chain_error_equality() {
    assert_eq!(ChainError::EmptyChain, ChainError::EmptyChain);
    assert_ne!(ChainError::EmptyChain, ChainError::CapabilityNotFound);
    assert_eq!(
        ChainError::InvalidToken { index: 5 },
        ChainError::InvalidToken { index: 5 }
    );
    assert_ne!(
        ChainError::InvalidToken { index: 5 },
        ChainError::InvalidToken { index: 6 }
    );
}

#[test]
fn test_verify_chain_empty() {
    let chain = CapabilityChain::empty();
    let result = verify_chain(&chain);
    assert!(matches!(result, Err(ChainError::EmptyChain)));
}

#[test]
fn test_is_chain_valid_empty() {
    let chain = CapabilityChain::empty();
    assert!(!is_chain_valid(&chain));
}

#[test]
fn test_effective_capabilities_empty_chain() {
    let chain = CapabilityChain::empty();
    let caps = effective_capabilities(&chain);
    assert!(caps.is_empty());
}

#[test]
fn test_effective_capabilities_single_token() {
    let tok = make_token(1, &[Capability::Admin, Capability::Debug]);
    let chain = CapabilityChain::single(tok);
    let caps = effective_capabilities(&chain);
    assert_eq!(caps.len(), 2);
    assert!(caps.contains(&Capability::Admin));
    assert!(caps.contains(&Capability::Debug));
}

#[test]
fn test_effective_capabilities_intersection() {
    let tok1 = make_token(1, &[Capability::Admin, Capability::Debug, Capability::Network]);
    let tok2 = make_token(2, &[Capability::Admin, Capability::Debug]);
    let mut chain = CapabilityChain::empty();
    chain.push(tok1);
    chain.push(tok2);
    let caps = effective_capabilities(&chain);
    assert_eq!(caps.len(), 2);
    assert!(caps.contains(&Capability::Admin));
    assert!(caps.contains(&Capability::Debug));
    assert!(!caps.contains(&Capability::Network));
}

#[test]
fn test_first_invalid_index_empty_chain() {
    let chain = CapabilityChain::empty();
    assert!(first_invalid_index(&chain).is_none());
}
