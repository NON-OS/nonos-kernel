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

// Per-arch halt-forever entry point. Kernel-core fatal-error paths
// reach this without naming an architecture. Each arch supplies its
// own implementation under its own `#[cfg(target_arch = "...")]` arm.
// On targets that have no implementation yet, the function does not
// exist; callers fail to compile, which is the intended behavior until
// that arch is brought up.

#[cfg(target_arch = "x86_64")]
pub use super::x86_64::boot::cpu_ops::halt_loop;
