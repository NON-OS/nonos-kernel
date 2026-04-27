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

use super::helpers::remove_recursive;
use alloc::string::String;

pub(super) fn cmd_rmdir(args: &[&str]) -> Result<(), String> {
    for path in args {
        if path.starts_with('-') {
            continue;
        }
        let _ = crate::fs::rmdir(path);
    }
    Ok(())
}

pub(super) fn cmd_rm(args: &[&str]) -> Result<(), String> {
    let mut recursive = false;
    let mut force = false;
    for arg in args {
        match *arg {
            "-r" | "-R" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "-rf" | "-fr" => {
                recursive = true;
                force = true;
            }
            path if !path.starts_with('-') => {
                if recursive {
                    let _ = remove_recursive(path);
                } else {
                    let result = crate::fs::unlink(path);
                    if result.is_err() && !force {
                        return Err(alloc::format!("rm failed: {}", path));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
