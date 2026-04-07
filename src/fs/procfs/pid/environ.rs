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

pub fn read_pid_environ(pid: i32) -> Result<Vec<u8>, i32> {
    let proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let envp = proc.envp.lock();
    if envp.is_empty() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::new();
    for env in envp.iter() {
        buf.extend(env.as_bytes());
        buf.push(0);
    }
    Ok(buf)
}

pub fn read_pid_environ_string(pid: i32) -> Result<String, i32> {
    let bytes = read_pid_environ(pid)?;
    let mut result = String::new();
    for byte in bytes {
        if byte == 0 {
            result.push('\n');
        } else {
            result.push(byte as char);
        }
    }
    Ok(result)
}

pub fn get_environ_vars(pid: i32) -> Result<Vec<(String, String)>, i32> {
    let bytes = read_pid_environ(pid)?;
    let mut vars = Vec::new();
    let mut current = String::new();
    for byte in bytes {
        if byte == 0 {
            if let Some(eq_pos) = current.find('=') {
                let (key, val) = current.split_at(eq_pos);
                vars.push((String::from(key), String::from(&val[1..])));
            }
            current.clear();
        } else {
            current.push(byte as char);
        }
    }
    Ok(vars)
}

pub fn get_environ_var(pid: i32, key: &str) -> Result<Option<String>, i32> {
    let vars = get_environ_vars(pid)?;
    Ok(vars.into_iter().find(|(k, _)| k == key).map(|(_, v)| v))
}
