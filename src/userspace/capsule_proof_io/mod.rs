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

//! NONOS proof_io capsule wiring. Embeds the userland binary at build
//! time, seeds it into the ramfs at boot, and runs it once via the
//! existing `exec_process` path so the SYSCALL-instruction → contract
//! round trip is exercised by a real user-mode caller.
//!
//! The whole module is feature-gated by `nonos-capsule-proof-io`. With
//! the feature off (the default), `seed` and `launch` are no-ops; the
//! kernel build does not reference any userland artifact and is fully
//! self-contained.

mod embed;
mod launch;
mod seed;

pub use launch::launch;
pub use seed::seed;
