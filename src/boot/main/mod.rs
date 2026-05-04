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

pub mod core_init;
pub mod mode;

// Dead-at-boot trees, kept as legacy reference. The live framebuffer
// init is `kernel_core::init::framebuffer`; the dead UI surfaces are
// migration backlog.
#[cfg(feature = "nonos-legacy-tree")]
pub mod desktop_run;
#[cfg(feature = "nonos-legacy-tree")]
pub mod graphics_init;
#[cfg(feature = "nonos-legacy-tree")]
pub mod setup_menu;

pub use core_init::init_core_systems;
pub use mode::{get_boot_mode, is_microkernel, BootMode};

#[cfg(feature = "nonos-legacy-tree")]
pub use desktop_run::{handle_dialogs, run_desktop};
#[cfg(feature = "nonos-legacy-tree")]
pub use graphics_init::{init_graphics, init_graphics_for_microkernel};
#[cfg(feature = "nonos-legacy-tree")]
pub use setup_menu::{apply_config, needs_setup, run_setup_menu, SetupConfig};
