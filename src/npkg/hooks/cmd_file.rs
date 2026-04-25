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

use super::helpers::path_exists;
use alloc::string::String;

pub(super) fn cmd_cp(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("cp: missing arguments"));
    }
    let src = args[args.len() - 2];
    let dst = args[args.len() - 1];
    let data =
        crate::fs::read_file_bytes(src).map_err(|_| alloc::format!("cp: cannot read {}", src))?;
    crate::fs::nonos_vfs::vfs_write_file(dst, &data)
        .map_err(|_| alloc::format!("cp: cannot write {}", dst))?;
    Ok(())
}

pub(super) fn cmd_mv(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("mv: missing arguments"));
    }
    let src = args[args.len() - 2];
    let dst = args[args.len() - 1];
    crate::fs::rename(src, dst).map_err(|_| alloc::format!("mv: failed {} -> {}", src, dst))?;
    Ok(())
}

pub(super) fn cmd_touch(args: &[&str]) -> Result<(), String> {
    for path in args {
        if path.starts_with('-') {
            continue;
        }
        if !path_exists(path) {
            let _ = crate::fs::nonos_vfs::vfs_write_file(path, &[]);
        }
        let now = crate::time::unix_timestamp();
        let _ = crate::fs::set_times(path, &[now, now]);
    }
    Ok(())
}
