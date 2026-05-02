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

// Syscall numbers this libc uses. Values match the kernel's
// `crate::syscall::numbers::SyscallNumber`; the kernel side is the
// source of truth.

pub(crate) const N_READ: i64 = 0;
pub(crate) const N_WRITE: i64 = 1;
pub(crate) const N_EXIT: i64 = 60;
