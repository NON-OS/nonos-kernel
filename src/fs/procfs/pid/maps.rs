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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub fn read_pid_maps(pid: i32) -> Result<String, i32> {
    let _proc = crate::process::get_process(pid as u32).ok_or(-3)?;
    let regions = crate::memory::get_process_vm_areas(pid as u32);
    let mut output = String::new();
    for (start, end, flags) in regions {
        let perms = format_permissions(flags);
        output.push_str(&format!(
            "{:016x}-{:016x} {} {:08x} 00:00 {:>8} \n",
            start, end, perms, 0u64, 0u64
        ));
    }
    Ok(output)
}

fn format_permissions(flags: u32) -> String {
    let r = if flags & 0x1 != 0 { 'r' } else { '-' };
    let w = if flags & 0x2 != 0 { 'w' } else { '-' };
    let x = if flags & 0x4 != 0 { 'x' } else { '-' };
    let p = if flags & 0x8 != 0 { 's' } else { 'p' };
    format!("{}{}{}{}", r, w, x, p)
}

#[derive(Debug, Clone)]
pub struct VmArea {
    pub start: u64,
    pub end: u64,
    pub flags: u32,
    pub offset: u64,
    pub dev_major: u8,
    pub dev_minor: u8,
    pub inode: u64,
    pub pathname: Option<String>,
}

pub fn parse_maps_line(line: &str) -> Option<VmArea> {
    let parts: Vec<&str> = line.splitn(6, |c| c == ' ' || c == '-').collect();
    if parts.len() < 5 {
        return None;
    }
    Some(VmArea {
        start: u64::from_str_radix(parts[0], 16).ok()?,
        end: u64::from_str_radix(parts[1], 16).ok()?,
        flags: parse_perms(parts[2]),
        offset: u64::from_str_radix(parts[3], 16).ok()?,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        pathname: parts.get(5).map(|s| String::from(*s)),
    })
}

fn parse_perms(s: &str) -> u32 {
    let mut flags = 0u32;
    if s.contains('r') {
        flags |= 0x1;
    }
    if s.contains('w') {
        flags |= 0x2;
    }
    if s.contains('x') {
        flags |= 0x4;
    }
    if s.contains('s') {
        flags |= 0x8;
    }
    flags
}
