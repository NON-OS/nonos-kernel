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
    let proc = crate::process::get_process(pid).ok_or(-3)?;
    let mem = proc.memory_info;
    if mem.arg_start == 0 || mem.arg_end == 0 {
        return Ok(Vec::new());
    }
    let len = (mem.arg_end - mem.arg_start) as usize;
    if len > 4096 * 32 {
        return Err(-14);
    }
    let mut buf = alloc::vec![0u8; len];
    crate::memory::read_process_memory(pid, mem.arg_start, &mut buf)?;
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
    Ok(result.trim_end().to_string())
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
