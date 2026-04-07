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

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub fn read_pid_cmdline(pid: i32) -> Result<Vec<u8>, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let argv = proc.argv.lock();
    if argv.is_empty() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::new();
    for arg in argv.iter() {
        buf.extend(arg.as_bytes());
        buf.push(0);
    }
    Ok(buf)
}

pub fn read_pid_cmdline_string(pid: i32) -> Result<String, i32> {
    let bytes = read_pid_cmdline(pid)?;
    let mut result = String::new();
    for byte in bytes {
        if byte == 0 {
            result.push(' ');
        } else {
            result.push(byte as char);
        }
    }
    Ok(String::from(result.trim_end()))
}

pub fn get_cmdline_args(pid: i32) -> Result<Vec<String>, i32> {
    let bytes = read_pid_cmdline(pid)?;
    let mut args = Vec::new();
    let mut current = String::new();
    for byte in bytes {
        if byte == 0 {
            if !current.is_empty() {
                args.push(current);
                current = String::new();
            }
        } else {
            current.push(byte as char);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}
