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

pub fn cmd_ln(args: &[&str]) -> Result<(), String> {
    let mut symbolic = false;
    let mut force = false;
    let mut targets = Vec::new();
    for arg in args {
        match *arg {
            "-s" | "--symbolic" => symbolic = true,
            "-f" | "--force" => force = true,
            "-sf" | "-fs" => {
                symbolic = true;
                force = true;
            }
            path if !path.starts_with('-') => targets.push(path),
            _ => {}
        }
    }
    if targets.len() < 2 {
        return Err(String::from("ln: missing arguments"));
    }
    let target = targets[0];
    let link = targets[1];
    if force {
        let _ = crate::fs::unlink(link);
    }
    if symbolic {
        crate::fs::symlink(target, link)
            .map_err(|_| alloc::format!("ln: failed {} -> {}", link, target))?;
    } else {
        crate::fs::link(target, link)
            .map_err(|_| alloc::format!("ln: failed {} -> {}", link, target))?;
    }
    Ok(())
}
