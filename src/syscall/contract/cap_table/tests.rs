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

//! Totality contract for the cap_table dispatcher.
//!
//! Properties under test:
//! 1. Every `SyscallNumber` reachable from `from_u64` is claimed by at
//!    least one family. A holey table denies silently via the
//!    `unwrap_or(false)` fallback in `is_allowed`; this test detects
//!    that hole by asserting that a fully-capable, valid token is
//!    granted access to every recognised number.
//! 2. An empty (and therefore invalid) token is denied access to every
//!    recognised number — the `is_valid()` precondition must hold for
//!    every family check.

use super::is_allowed;
use crate::capabilities::{Capability, CapabilityToken};
use crate::syscall::numbers::SyscallNumber;

// Walk the integer range that covers every assigned syscall number in
// `numbers/defs.rs`. Numbers outside this range either do not exist or
// are reserved; they cannot be reached through `from_u64`.
const SCAN_LIMIT: u64 = 4096;

fn full_token() -> CapabilityToken {
    CapabilityToken::with_caps(&Capability::all())
}

fn empty_token() -> CapabilityToken {
    CapabilityToken::empty()
}

#[test]
fn full_token_allows_every_recognised_syscall() {
    let token = full_token();
    let mut denied: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    for n in 0u64..SCAN_LIMIT {
        if let Some(num) = SyscallNumber::from_u64(n) {
            if !is_allowed(&token, num) {
                denied.push(n);
            }
        }
    }
    assert!(
        denied.is_empty(),
        "cap_table is not total: {} recognised SyscallNumber(s) unclaimed: first 16 = {:?}",
        denied.len(),
        &denied[..denied.len().min(16)]
    );
}

#[test]
fn empty_token_denies_every_recognised_syscall() {
    let token = empty_token();
    let mut allowed: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    for n in 0u64..SCAN_LIMIT {
        if let Some(num) = SyscallNumber::from_u64(n) {
            if is_allowed(&token, num) {
                allowed.push(n);
            }
        }
    }
    assert!(
        allowed.is_empty(),
        "empty token granted {} recognised SyscallNumber(s): first 16 = {:?}",
        allowed.len(),
        &allowed[..allowed.len().min(16)]
    );
}
