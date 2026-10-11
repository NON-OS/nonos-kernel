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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use nonos_app_skeleton::clients::vfs;
use nonos_libc::mk_getpid;

use super::dl_name::unique_name;
use super::store::gate;

const DIR: &str = "/home/Downloads";
const OFFLINE: &str = "file server unavailable";

/// Writes `body` into the Downloads folder under `name`, or under the first
/// free `name (N)` when that is taken. Returns the name it was saved as.
pub fn save(name: &str, body: &[u8]) -> Result<String, &'static str> {
    let pid = mk_getpid();
    if !gate::live() || pid == 0 {
        return Err(OFFLINE);
    }
    if let Err(err) = vfs::mkdir(pid, DIR.as_bytes()) {
        gate::note(err);
    }
    if !gate::live() {
        return Err(OFFLINE);
    }
    let prefix = format!("{}/", DIR);
    let listed = vfs::list_paths(pid, prefix.as_bytes()).map_err(note)?;
    let existing: Vec<String> = listed
        .iter()
        .filter_map(|p| p.strip_prefix(prefix.as_str()))
        .map(|rest| String::from(rest.split('/').next().unwrap_or("")))
        .collect();
    let file = unique_name(&existing, name);
    let path = format!("{}{}", prefix, file);
    vfs::write_file(pid, path.as_bytes(), body).map_err(note)?;
    vfs::persist(pid, path.as_bytes()).map_err(note)?;
    Ok(file)
}

fn note(err: &'static str) -> &'static str {
    gate::note(err);
    err
}
