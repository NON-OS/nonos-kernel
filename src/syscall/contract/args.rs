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

/// Six raw syscall argument registers, in the order the per-arch shim
/// extracted them. Interpretation as pointers, integers, or flag words
/// is the handler's job, not the contract's.
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs(pub [u64; 6]);

impl SyscallArgs {
    #[inline]
    pub const fn new(args: [u64; 6]) -> Self {
        Self(args)
    }

    #[inline]
    pub const fn raw(&self) -> [u64; 6] {
        self.0
    }

    #[inline]
    pub const fn arg(&self, i: usize) -> u64 {
        self.0[i]
    }
}
