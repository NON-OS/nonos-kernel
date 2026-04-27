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

use super::helpers::create_parents;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn cmd_mkdir(args: &[&str]) -> Result<(), String> {
    let mut parents = false;
    let mut mode = 0o755u32;
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-p" => parents = true,
            "-m" => {
                i += 1;
                if i < args.len() {
                    mode = u32::from_str_radix(args[i], 8).unwrap_or(0o755);
                }
            }
            arg if !arg.starts_with('-') => paths.push(arg),
            _ => {}
        }
        i += 1;
    }
    for path in paths {
        if parents {
            create_parents(path, mode)?;
        } else {
            crate::fs::mkdir(path, mode).map_err(|_| alloc::format!("mkdir failed: {}", path))?;
        }
    }
    Ok(())
}
