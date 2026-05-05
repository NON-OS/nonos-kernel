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

pub mod fallback;
pub mod oom;
pub mod security;

// `kernel_main` is the alternate boot entry point invoked through the
// `arch::x86_64::boot::entry::boot_late` chain, which is itself gated
// to legacy. Production microkernel boot enters via
// `nonos_main::_start → kernel_entry → kernel_core::microkernel_init`
// then `microkernel_main`; no active-build caller reaches
// `entry::kernel_main`. Quarantined here with its VGA helpers so the
// active microkernel surface only exposes what the production boot
// actually consumes.

// Desktop loop, network bring-up, and the desktop-context helper are
// not on the microkernel boot path. Capsules carry any UI/network as
// their own userland.

pub use oom::handle_oom;
