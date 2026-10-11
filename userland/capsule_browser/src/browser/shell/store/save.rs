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

use super::codec::{self, Persisted};
use super::merge::{merge, Removed};
use super::{gate, load, paths};

/// Writes `mine` merged with the record on disk, best effort, and returns
/// what it wrote: another window may have saved since this one loaded. The
/// owner pid is this window's own, as the vfs server rejects a claimed
/// owner that is not the sender. A refused step leaves the live state as it
/// is for this session. Called from event handlers only, never on a frame
/// path.
pub fn save(mine: Persisted, removed: Removed) -> Persisted {
    let pid = mk_getpid();
    if !gate::live() || pid == 0 {
        return mine;
    }
    let p = merge(load::read(pid), mine, removed);
    if let Err(err) = vfs::mkdir(pid, paths::DIR) {
        gate::note(err);
    }
    if !gate::live() {
        return p;
    }
    if let Err(err) = vfs::write_file(pid, paths::STATE, &codec::encode(&p)) {
        gate::note(err);
        return p;
    }
    if let Err(err) = vfs::persist(pid, paths::STATE) {
        gate::note(err);
    }
    p
}
