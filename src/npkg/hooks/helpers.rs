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

use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn path_exists(path: &str) -> bool {
    crate::fs::vfs::get_vfs().map(|vfs| vfs.exists(path)).unwrap_or(false)
}

pub(super) fn create_parents(path: &str, mode: u32) -> Result<(), String> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();
    for component in components {
        current.push('/');
        current.push_str(component);
        if !path_exists(&current) {
            crate::fs::mkdir(&current, mode)
                .map_err(|_| alloc::format!("mkdir failed: {}", current))?;
        }
    }
    Ok(())
}

pub(super) fn remove_recursive(path: &str) -> Result<(), String> {
    if crate::fs::is_directory(path) {
        if let Some(entries) = crate::fs::vfs::get_vfs().and_then(|v| v.list_dir(path).ok()) {
            for entry in entries {
                let full = alloc::format!("{}/{}", path, entry);
                remove_recursive(&full)?;
            }
        }
        let _ = crate::fs::rmdir(path);
    } else {
        let _ = crate::fs::unlink(path);
    }
    Ok(())
}

pub(super) fn parse_owner(s: &str) -> Result<(u32, u32), String> {
    if let Some((user, group)) = s.split_once(':') {
        let uid = user.parse().unwrap_or(0);
        let gid = group.parse().unwrap_or(0);
        Ok((uid, gid))
    } else {
        let uid = s.parse().unwrap_or(0);
        Ok((uid, uid))
    }
}
