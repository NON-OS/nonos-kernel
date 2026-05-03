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

//! Kernel-side scaffolding for the wallpaper userland capsule.
//!
//! Phase 3 / M3 graphics proof: a CPL=3 binary that exercises the full
//! Phase 1 surface contract (display dimensions → create → map → fill →
//! present → destroy) and exits. Off by default behind the
//! `nonos-capsule-wallpaper` feature.

mod embed;
mod error;
mod spawn;

pub use error::SpawnError;
pub use spawn::spawn_wallpaper_capsule;
