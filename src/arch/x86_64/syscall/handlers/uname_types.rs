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

#[repr(C)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl Utsname {
    pub const SIZE: usize = 390;

    pub fn new() -> Self {
        let mut uts = Self {
            sysname: [0u8; 65],
            nodename: [0u8; 65],
            release: [0u8; 65],
            version: [0u8; 65],
            machine: [0u8; 65],
            domainname: [0u8; 65],
        };
        Self::copy_field(&mut uts.sysname, b"NONOS");
        Self::copy_field(&mut uts.nodename, b"nonos");
        Self::copy_field(&mut uts.release, b"0.1.0");
        Self::copy_field(&mut uts.version, b"#1 SMP PREEMPT");
        Self::copy_field(&mut uts.machine, b"x86_64");
        Self::copy_field(&mut uts.domainname, b"(none)");
        uts
    }

    fn copy_field(dst: &mut [u8; 65], src: &[u8]) {
        let len = src.len().min(64);
        dst[..len].copy_from_slice(&src[..len]);
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(self as *const Self as *const u8, Self::SIZE)
        }
    }
}

impl Default for Utsname {
    fn default() -> Self {
        Self::new()
    }
}
