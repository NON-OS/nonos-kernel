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

//! Syscall entry contract. Shared dispatch with a structurally
//! unbypassable capability check. Per-arch entry shims call
//! `dispatch(SyscallNumber, SyscallArgs)` after extracting the syscall
//! number and the six argument registers. The x86_64 shim lives in
//! `crate::arch::x86_64::syscall::manager::entry`. aarch64 and riscv64
//! shims will live in `crate::arch::{aarch64,riscv64}::syscall` when
//! those backends are added; the contract surface they call into does
//! not change.

mod args;
mod cap_table;
mod capability;
mod dispatch;

pub use args::SyscallArgs;
pub use capability::Capability;
pub use dispatch::dispatch;
