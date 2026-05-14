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

// Compile-time embed of the userland wallpaper binary. The
// userland crate must be built first (`make nonos-mk-wallpaper`)
// or the kernel build with `nonos-capsule-wallpaper` will fail
// at this `include_bytes!` with a clear file-not-found.
#[cfg(feature = "nonos-capsule-wallpaper")]
pub(crate) const WALLPAPER_ELF: &[u8] = include_bytes!(
    "../../../userland/capsule_wallpaper/target/x86_64-nonos-user/release/wallpaper"
);

#[cfg(not(feature = "nonos-capsule-wallpaper"))]
pub(crate) const WALLPAPER_ELF: &[u8] = &[];

pub(crate) const WALLPAPER_PATH: &str = "/capsules/wallpaper";
