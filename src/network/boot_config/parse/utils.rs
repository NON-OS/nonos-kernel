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
use alloc::vec::Vec;

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u8>() {
            Ok(n) => ip[i] = n,
            Err(_) => return None,
        }
    }
    Some(ip)
}

pub fn init_from_handoff() {
    use crate::boot::handoff::get_handoff;
    if let Some(handoff) = get_handoff() {
        if let Some(cmdline) = unsafe { handoff.cmdline() } {
            crate::log::info!("net: found boot cmdline: {}", cmdline);
            super::cmdline::parse_cmdline(cmdline);
        } else {
            crate::log::info!("net: no cmdline, using default config");
        }
    }
}
