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

//! NONOS wallpaper capsule wiring. One-shot graphics proof. Embeds
//! the userland binary at build time, seeds it into the ramfs at
//! boot, and runs it once via `exec_process` to drive the
//! display_dimensions / surface_create / surface_map /
//! surface_present_full / surface_destroy round trip from CPL=3.
//!
//! Feature-gated by `nonos-capsule-wallpaper`. With the feature
//! off, `seed` and `launch` are no-ops; the kernel build does not
//! reference any userland artifact.

pub(crate) mod embed;
mod launch;
mod seed;
mod spawn;
mod state;

pub use launch::launch;
pub use seed::seed;
pub use spawn::spawn_wallpaper_capsule;
pub use state::shared_state;
