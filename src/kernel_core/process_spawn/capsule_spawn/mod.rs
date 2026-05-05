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

//! Shared capsule spawn pipeline. Each capsule kernel module passes a
//! `CapsuleSpec` describing its name, ports, embedded ELF, and caps;
//! `runner::spawn` runs the kernel-primitive dance — endpoint
//! registration, process creation, ELF load in capsule AS, kernel and
//! user stacks, iretq frame, run-queue insert. The capsule's own
//! `spawn.rs` only adds policy: which spec, and `state::set_alive`
//! after success.

mod runner;
mod spec;

pub use runner::spawn;
pub use spec::{CapsuleSpec, SpawnError};
