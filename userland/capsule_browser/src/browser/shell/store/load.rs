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

use nonos_app_skeleton::clients::vfs;
use nonos_libc::mk_getpid;

use super::codec::Persisted;
use super::decode::decode;
use super::{gate, paths};

/* `Browser::new` runs before the window opens, so a VFS still staging
 * packages must not hold the window hostage: the read gets a short bound
 * and a miss falls back to defaults. A slow answer is not proof the server
 * is dead, so it does not latch the gate. */
const LOAD_TIMEOUT_MS: u64 = 500;

/// The saved bookmarks, or none when there is no VFS, no file yet, or a
/// record this build cannot read. Called from `Browser::new`, never on a
/// frame path.
pub fn load() -> Persisted {
    let pid = mk_getpid();
    if !gate::live() || pid == 0 {
        return Persisted::default();
    }
    read(pid)
}

/// The record on disk now, or the defaults when there is none to read.
pub(super) fn read(pid: u32) -> Persisted {
    match vfs::read_file_within(pid, paths::STATE, paths::MAX_FILE_BYTES, LOAD_TIMEOUT_MS) {
        Ok(bytes) => decode(&bytes),
        Err(_) => Persisted::default(),
    }
}
