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

use crate::capabilities::CapabilityToken;
use crate::syscall::caps::current_caps;
use crate::syscall::numbers::SyscallNumber;

use super::args::SyscallArgs;
use super::cap_table;

/// Witness that a syscall has passed the capability check for a specific
/// `SyscallNumber` plus argument set.
///
/// The only constructor is `Capability::resolve`. User-space code cannot
/// construct one; in-kernel code outside the contract module also cannot,
/// because the wrapped token field is private. A handler that takes
/// `Capability` therefore has executable proof that the check ran.
pub struct Capability {
    token: CapabilityToken,
}

impl Capability {
    /// Resolve the calling thread's current capability token against the
    /// requirement of `number`. Returns `Some` only when the token is
    /// valid and grants the syscall's required permission.
    ///
    /// `_args` is taken to keep the door open for argument-aware checks
    /// (e.g. fd-bound capabilities) without a signature change later.
    /// Today the per-syscall mapping is argument-agnostic.
    pub fn resolve(number: SyscallNumber, _args: &SyscallArgs) -> Option<Self> {
        let token = current_caps()?;
        if !cap_table::is_allowed(&token, number) {
            return None;
        }
        Some(Self { token })
    }

    /// Borrow the underlying capability token. Handlers that need to
    /// inspect specific bits reach the token through here.
    #[inline]
    pub fn token(&self) -> &CapabilityToken {
        &self.token
    }
}
