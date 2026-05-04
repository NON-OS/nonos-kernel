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
pub mod kernel_main;
pub mod oom;
pub mod security;
pub mod vga_error;

// Desktop loop, network bring-up, and the desktop-context helper are
// not on the microkernel boot path. The microkernel `kernel_main`
// routes straight from boot init into the scheduler; capsules carry
// any UI/network as their own userland.
#[cfg(feature = "nonos-legacy-tree")]
pub mod context;
#[cfg(feature = "nonos-legacy-tree")]
pub mod desktop_loop;
#[cfg(feature = "nonos-legacy-tree")]
pub mod network;

pub use kernel_main::kernel_main;
pub use oom::handle_oom;
pub use vga_error::{early_vga_error, halt_loop};
