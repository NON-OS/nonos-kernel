// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub fn syscall_uname(buf: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if buf == 0 {
        return (-14i64) as u64;
    }

    let utsname = buf as *mut Utsname;

    unsafe {
        core::ptr::write_bytes(utsname, 0, 1);

        let sysname = b"NONOS";
        let nodename = b"nonos";
        let release = b"0.1.0";
        let version = b"#1 SMP PREEMPT";
        let machine = b"x86_64";
        let domainname = b"(none)";

        core::ptr::copy_nonoverlapping(sysname.as_ptr(), core::ptr::addr_of_mut!((*utsname).sysname).cast(), sysname.len());
        core::ptr::copy_nonoverlapping(nodename.as_ptr(), core::ptr::addr_of_mut!((*utsname).nodename).cast(), nodename.len());
        core::ptr::copy_nonoverlapping(release.as_ptr(), core::ptr::addr_of_mut!((*utsname).release).cast(), release.len());
        core::ptr::copy_nonoverlapping(version.as_ptr(), core::ptr::addr_of_mut!((*utsname).version).cast(), version.len());
        core::ptr::copy_nonoverlapping(machine.as_ptr(), core::ptr::addr_of_mut!((*utsname).machine).cast(), machine.len());
        core::ptr::copy_nonoverlapping(domainname.as_ptr(), core::ptr::addr_of_mut!((*utsname).domainname).cast(), domainname.len());
    }

    0
}
