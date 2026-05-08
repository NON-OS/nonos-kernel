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

/// Place the embedded wallpaper ELF into the ramfs at the
/// well-known path. Called once at boot, after `init_nonos_fs`
/// has created the `/capsules/.dir` marker.
pub fn seed() {
    if WALLPAPER_ELF.is_empty() {
        return;
    }
    match crate::fs::ramfs::create_file(WALLPAPER_PATH, WALLPAPER_ELF) {
        Ok(()) => {
            crate::sys::serial::println(b"[NONOS] wallpaper capsule seeded at /capsules/wallpaper");
        }
        Err(e) => {
            crate::sys::serial::println(b"[NONOS] wallpaper seed failed:");
            crate::sys::serial::println(e.as_str().as_bytes());
        }
    }
}
