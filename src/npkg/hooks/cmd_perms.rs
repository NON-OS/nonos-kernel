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

use super::helpers::parse_owner;
use alloc::string::String;

pub(super) fn cmd_chmod(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("chmod: missing arguments"));
    }
    let mode = u32::from_str_radix(args[0], 8).map_err(|_| String::from("chmod: invalid mode"))?;
    for path in &args[1..] {
        let _ = crate::fs::chmod(path, mode);
    }
    Ok(())
}

pub(super) fn cmd_chown(args: &[&str]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(String::from("chown: missing arguments"));
    }
    let owner = args[0];
    let (uid, gid) = parse_owner(owner)?;
    for path in &args[1..] {
        let _ = crate::fs::chown(path, uid, gid);
    }
    Ok(())
}
