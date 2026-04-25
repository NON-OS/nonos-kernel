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

use crate::capabilities::*;
use crate::test::framework::TestResult;

fn make_token(owner: u64, caps: &[Capability]) -> CapabilityToken {
    CapabilityToken {
        owner_module: owner,
        permissions: caps.to_vec(),
        expires_at_ms: None,
        nonce: 12345,
        signature: [0u8; 64],
    }
}

pub(crate) fn test_capability_chain_new() -> TestResult {
    let tokens = alloc::vec![make_token(1, &[Capability::Admin])];
    let chain = CapabilityChain::new(tokens);
    if chain.len() != 1 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    if !chain.is_empty() { return TestResult::Fail; }
    if chain.len() != 0 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_single() -> TestResult {
    let tok = make_token(42, &[Capability::Admin]);
    let chain = CapabilityChain::single(tok);
    if chain.len() != 1 { return TestResult::Fail; }
    if chain.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_push() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    if chain.len() != 2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_pop() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let popped = chain.pop();
    if popped.is_none() { return TestResult::Fail; }
    if popped.unwrap().owner_module != 2 { return TestResult::Fail; }
    if chain.len() != 1 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_pop_empty() -> TestResult {
    let mut chain = CapabilityChain::empty();
    if chain.pop().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_root() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let root = chain.root().unwrap();
    if root.owner_module != 1 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_root_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    if chain.root().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_leaf() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let leaf = chain.leaf().unwrap();
    if leaf.owner_module != 2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_leaf_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    if chain.leaf().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_get() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    if chain.get(0).unwrap().owner_module != 1 { return TestResult::Fail; }
    if chain.get(1).unwrap().owner_module != 2 { return TestResult::Fail; }
    if chain.get(2).is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_tokens() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(2, &[Capability::Debug]));
    let tokens = chain.tokens();
    if tokens.len() != 2 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_final_owner() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(1, &[Capability::Admin]));
    chain.push(make_token(99, &[Capability::Debug]));
    if chain.final_owner() != Some(99) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_final_owner_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    if chain.final_owner().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_root_owner() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(42, &[Capability::Admin]));
    chain.push(make_token(99, &[Capability::Debug]));
    if chain.root_owner() != Some(42) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_root_owner_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    if chain.root_owner().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_max_depth() -> TestResult {
    if CapabilityChain::max_depth() != MAX_CHAIN_DEPTH { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_default() -> TestResult {
    let chain = CapabilityChain::default();
    if !chain.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_capability_chain_display() -> TestResult {
    let mut chain = CapabilityChain::empty();
    chain.push(make_token(10, &[Capability::Admin]));
    chain.push(make_token(20, &[Capability::Debug]));
    let display = alloc::format!("{}", chain);
    if !display.contains("len:2") { return TestResult::Fail; }
    if !display.contains("root:10") { return TestResult::Fail; }
    if !display.contains("leaf:20") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_max_chain_depth_constant() -> TestResult {
    if MAX_CHAIN_DEPTH != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_max_chain_depth_function() -> TestResult {
    if max_chain_depth() != 16 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_empty_chain_as_str() -> TestResult {
    let err = ChainError::EmptyChain;
    if err.as_str() != "Chain is empty" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_too_deep_as_str() -> TestResult {
    let err = ChainError::TooDeep { depth: 20, max: 16 };
    if err.as_str() != "Chain exceeds maximum depth" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_invalid_token_as_str() -> TestResult {
    let err = ChainError::InvalidToken { index: 5 };
    if err.as_str() != "Token signature invalid" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_expired_token_as_str() -> TestResult {
    let err = ChainError::ExpiredToken { index: 3 };
    if err.as_str() != "Token has expired" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_broken_link_as_str() -> TestResult {
    let err = ChainError::BrokenLink { index: 2 };
    if err.as_str() != "Chain link broken" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_capability_not_found_as_str() -> TestResult {
    let err = ChainError::CapabilityNotFound;
    if err.as_str() != "Capability not in chain" { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_is_recoverable_expired() -> TestResult {
    let err = ChainError::ExpiredToken { index: 0 };
    if !err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_is_recoverable_cap_not_found() -> TestResult {
    let err = ChainError::CapabilityNotFound;
    if !err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_is_recoverable_empty() -> TestResult {
    let err = ChainError::EmptyChain;
    if err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_is_recoverable_invalid() -> TestResult {
    let err = ChainError::InvalidToken { index: 0 };
    if err.is_recoverable() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_failed_index_invalid_token() -> TestResult {
    let err = ChainError::InvalidToken { index: 5 };
    if err.failed_index() != Some(5) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_failed_index_expired_token() -> TestResult {
    let err = ChainError::ExpiredToken { index: 3 };
    if err.failed_index() != Some(3) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_failed_index_broken_link() -> TestResult {
    let err = ChainError::BrokenLink { index: 7 };
    if err.failed_index() != Some(7) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_failed_index_empty_chain() -> TestResult {
    let err = ChainError::EmptyChain;
    if err.failed_index().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_failed_index_cap_not_found() -> TestResult {
    let err = ChainError::CapabilityNotFound;
    if err.failed_index().is_some() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_display_empty_chain() -> TestResult {
    let err = ChainError::EmptyChain;
    let display = alloc::format!("{}", err);
    if !display.contains("empty") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_display_too_deep() -> TestResult {
    let err = ChainError::TooDeep { depth: 20, max: 16 };
    let display = alloc::format!("{}", err);
    if !display.contains("20") { return TestResult::Fail; }
    if !display.contains("16") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_display_invalid_token() -> TestResult {
    let err = ChainError::InvalidToken { index: 5 };
    let display = alloc::format!("{}", err);
    if !display.contains("5") { return TestResult::Fail; }
    if !display.contains("invalid") { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_chain_error_equality() -> TestResult {
    if ChainError::EmptyChain != ChainError::EmptyChain { return TestResult::Fail; }
    if ChainError::EmptyChain == ChainError::CapabilityNotFound { return TestResult::Fail; }
    let e1 = ChainError::InvalidToken { index: 5 };
    let e2 = ChainError::InvalidToken { index: 5 };
    let e3 = ChainError::InvalidToken { index: 6 };
    if e1 != e2 { return TestResult::Fail; }
    if e1 == e3 { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_verify_chain_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    let result = verify_chain(&chain);
    if !matches!(result, Err(ChainError::EmptyChain)) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_is_chain_valid_empty() -> TestResult {
    let chain = CapabilityChain::empty();
    if is_chain_valid(&chain) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_effective_capabilities_empty_chain() -> TestResult {
    let chain = CapabilityChain::empty();
    let caps = effective_capabilities(&chain);
    if !caps.is_empty() { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_effective_capabilities_single_token() -> TestResult {
    let tok = make_token(1, &[Capability::Admin, Capability::Debug]);
    let chain = CapabilityChain::single(tok);
    let caps = effective_capabilities(&chain);
    if caps.len() != 2 { return TestResult::Fail; }
    if !caps.contains(&Capability::Admin) { return TestResult::Fail; }
    if !caps.contains(&Capability::Debug) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_effective_capabilities_intersection() -> TestResult {
    let tok1 = make_token(1, &[Capability::Admin, Capability::Debug, Capability::Network]);
    let tok2 = make_token(2, &[Capability::Admin, Capability::Debug]);
    let mut chain = CapabilityChain::empty();
    chain.push(tok1);
    chain.push(tok2);
    let caps = effective_capabilities(&chain);
    if caps.len() != 2 { return TestResult::Fail; }
    if !caps.contains(&Capability::Admin) { return TestResult::Fail; }
    if !caps.contains(&Capability::Debug) { return TestResult::Fail; }
    if caps.contains(&Capability::Network) { return TestResult::Fail; }
    TestResult::Pass
}

pub(crate) fn test_first_invalid_index_empty_chain() -> TestResult {
    let chain = CapabilityChain::empty();
    if first_invalid_index(&chain).is_some() { return TestResult::Fail; }
    TestResult::Pass
}
