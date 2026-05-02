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

use super::embed::{PROOF_IO_ELF, PROOF_IO_PATH};

/// Place the embedded proof_io ELF into the ramfs at the well-known
/// path. Called once at boot, after `init_nonos_fs` has created the
/// `/capsules/.dir` marker.
pub fn seed() {
    if PROOF_IO_ELF.is_empty() {
        return;
    }
    match crate::fs::ramfs::create_file(PROOF_IO_PATH, PROOF_IO_ELF) {
        Ok(()) => {
            crate::sys::serial::println(b"[NONOS] proof_io capsule seeded at /capsules/proof_io");
        }
        Err(e) => {
            crate::sys::serial::println(b"[NONOS] proof_io seed failed:");
            crate::sys::serial::println(e.as_str().as_bytes());
        }
    }
}
