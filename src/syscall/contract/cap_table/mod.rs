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

mod admin;
mod crypto;
mod debug;
mod file_fs;
mod hardware;
mod io_event;
mod ipc;
mod memory;
mod network;
mod process_sched;
mod signal;
mod time;

use crate::capabilities::CapabilityToken;
use crate::syscall::numbers::SyscallNumber;

/// Map a syscall number to whether the supplied token grants it.
///
/// Each per-family helper returns `Some(true)` or `Some(false)` when the
/// number falls in its family, or `None` when it does not. The dispatcher
/// walks the families in order; a number not claimed by any family
/// admits on token validity alone — the kernel's syscall surface still
/// evolves and silent panics on unrecognised numbers would be the wrong
/// refusal mode.
pub(super) fn is_allowed(caps: &CapabilityToken, number: SyscallNumber) -> bool {
    file_fs::check(caps, number)
        .or_else(|| memory::check(caps, number))
        .or_else(|| process_sched::check(caps, number))
        .or_else(|| signal::check(caps, number))
        .or_else(|| time::check(caps, number))
        .or_else(|| network::check(caps, number))
        .or_else(|| ipc::check(caps, number))
        .or_else(|| crypto::check(caps, number))
        .or_else(|| admin::check(caps, number))
        .or_else(|| hardware::check(caps, number))
        .or_else(|| debug::check(caps, number))
        .or_else(|| io_event::check(caps, number))
        .unwrap_or_else(|| caps.is_valid())
}
