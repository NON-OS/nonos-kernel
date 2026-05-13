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

//! Trap delivery contract. Per-arch entry shims hand a captured trap
//! frame to `deliver` after applying the trait projection in `frame`.
//! The contract owns synchronous-exception classification and the three
//! policy buckets (user fault, kernel fault, fatal); IRQs, IPIs, NMIs
//! reaching this surface are classified as fatal with the rest, but
//! routine asynchronous delivery (registered IRQ handlers, IPI
//! dispatch) stays in the per-arch shim because the contract has no
//! portable policy work to do for those. Per-arch primitives (fatal
//! report sink and CPU halt) live behind `backend`.
//!
//! Current implementation status: only x86_64 is wired. aarch64 and
//! riscv64 are structurally accounted for — the contract surface,
//! `TrapFrame` trait, `TrapCause`, and `backend` dispatch hub are
//! architecture-neutral, with explicit insertion points for those
//! arches: a `backend_aarch64` / `backend_riscv64` module behind the
//! `cfg` switch in `backend.rs`, plus a `TrapFrame` impl alongside the
//! per-arch entry shim that performs cause projection from the
//! arch-native status registers. None of that is implemented yet, and
//! a build for those targets fails at `backend.rs` until it is.

mod backend;
#[cfg(target_arch = "aarch64")]
mod backend_aarch64;
#[cfg(target_arch = "riscv64")]
mod backend_riscv64;
#[cfg(target_arch = "x86_64")]
mod backend_x86_64;
mod cause;
mod class;
mod delivery;
mod fatal;
mod frame;
mod policy;
mod signal;

pub use cause::{FaultAccess, PageFaultInfo, TrapCause};
pub use class::{FaultKind, TrapClass};
pub use delivery::deliver;
pub use frame::TrapFrame;
