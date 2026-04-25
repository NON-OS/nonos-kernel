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

pub const AF_UNIX: u16 = 1;
pub const UNIX_PATH_MAX: usize = 108;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockaddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; UNIX_PATH_MAX],
}

impl Default for SockaddrUn {
    fn default() -> Self {
        Self { sun_family: AF_UNIX, sun_path: [0; UNIX_PATH_MAX] }
    }
}

impl SockaddrUn {
    pub fn new(path: &str) -> Self {
        let mut addr = Self::default();
        let bytes = path.as_bytes();
        let len = bytes.len().min(UNIX_PATH_MAX - 1);
        addr.sun_path[..len].copy_from_slice(&bytes[..len]);
        addr
    }
    pub fn path(&self) -> String {
        let end = self.sun_path.iter().position(|&c| c == 0).unwrap_or(UNIX_PATH_MAX);
        String::from_utf8_lossy(&self.sun_path[..end]).into_owned()
    }
    pub fn is_abstract(&self) -> bool {
        self.sun_path[0] == 0 && self.sun_path[1] != 0
    }
    pub fn abstract_name(&self) -> Option<String> {
        if self.is_abstract() {
            let end = self.sun_path[1..].iter().position(|&c| c == 0).unwrap_or(UNIX_PATH_MAX - 1);
            Some(String::from_utf8_lossy(&self.sun_path[1..1 + end]).into_owned())
        } else {
            None
        }
    }
}

pub fn parse_unix_address(addr_ptr: u64, addr_len: usize) -> Result<SockaddrUn, i32> {
    if addr_len < 2 {
        return Err(-22);
    }
    let addr: SockaddrUn = crate::usercopy::read_user_value(addr_ptr).map_err(|e| i32::from(e))?;
    if addr.sun_family != AF_UNIX {
        return Err(-97);
    }
    Ok(addr)
}

pub fn format_unix_address(path: &str) -> SockaddrUn {
    SockaddrUn::new(path)
}

pub fn address_len(addr: &SockaddrUn) -> usize {
    let path_len = addr.sun_path.iter().position(|&c| c == 0).unwrap_or(UNIX_PATH_MAX);
    2 + path_len + 1
}
