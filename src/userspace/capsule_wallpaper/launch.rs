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

use super::embed::{WALLPAPER_ELF, WALLPAPER_PATH};

/// Run the wallpaper capsule once. The current process's address
/// space is replaced by the wallpaper binary and control transfers
/// to its `_start` in CPL=3. The binary drives the graphics
/// syscall round trip (display_dimensions, surface_create,
/// surface_map, surface_present_full, surface_destroy) and exits.
///
/// Off when the `nonos-capsule-wallpaper` feature is disabled.
/// The init PCB carries Read/Write/Exit by default plus the
/// graphics caps the contract gates use; no mint-site change is
/// needed for this proof.
pub fn launch() {
    if WALLPAPER_ELF.is_empty() {
        return;
    }
    crate::sys::serial::println(b"[NONOS] wallpaper: launching from /capsules/wallpaper");
    let _ = crate::process::exec_process(WALLPAPER_PATH, &[], &[]);
    crate::sys::serial::println(b"[NONOS] wallpaper: launch returned (load failure)");
}
