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

//! Syscall authority resolver. The seam between the live token
//! handle on the PCB and the dispatch decision.
//!
//! Today the decision is the existing `is_valid()` + cap_table
//! membership check. The `ResolveContext` carries the boot-session
//! nonce, current ASID, and per-capsule revocation epoch that the
//! token already binds at mint, so turning each of those into a
//! hard check in the next sub-step is a body-of-function change
//! only — no signature, no caller, no token-type changes.

use alloc::sync::Arc;

use crate::capabilities::CapabilityToken;
use crate::syscall::numbers::SyscallNumber;

use super::args::SyscallArgs;
use super::cap_table;

// Fields are bound at the call site and will be consumed by the
// new resolver checks in the next sub-step. Kept unread for now so
// this commit changes no syscall behavior. `boot_session_nonce` is
// an `Option` so a syscall resolved before the boot singleton is
// latched is detectable rather than silently zero-bound.
#[allow(dead_code)]
pub(super) struct ResolveContext {
    pub current_asid: u32,
    pub boot_session_nonce: Option<[u8; 16]>,
    pub capsule_revocation_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolverError {
    InvalidToken,
    SyscallNotPermitted,
}

pub(super) fn resolve(
    token: &Arc<CapabilityToken>,
    number: SyscallNumber,
    _args: &SyscallArgs,
    _ctx: &ResolveContext,
) -> Result<(), ResolverError> {
    if !token.is_valid() {
        return Err(ResolverError::InvalidToken);
    }
    if !cap_table::is_allowed(token, number) {
        return Err(ResolverError::SyscallNotPermitted);
    }
    Ok(())
}
