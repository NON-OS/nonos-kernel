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

use core::arch::asm;

use super::error::SbiError;

const EID_BASE: usize = 0x10;

const FID_GET_SPEC_VERSION: usize = 0;
const FID_GET_IMPL_ID: usize = 1;
const FID_GET_IMPL_VERSION: usize = 2;
const FID_PROBE_EXTENSION: usize = 3;
const FID_GET_MVENDORID: usize = 4;
const FID_GET_MARCHID: usize = 5;
const FID_GET_MIMPID: usize = 6;

#[repr(C)]
pub struct SbiRet {
    pub error: isize,
    pub value: usize,
}

pub fn sbi_call(eid: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> SbiRet {
    let error: isize;
    let value: usize;

    unsafe {
        asm!(
            "ecall",
            inout("a0") a0 => error,
            inout("a1") a1 => value,
            in("a2") a2,
            in("a6") fid,
            in("a7") eid,
            options(nostack)
        );
    }

    SbiRet { error, value }
}

pub fn sbi_version() -> Result<(u32, u32), SbiError> {
    let ret = sbi_call(EID_BASE, FID_GET_SPEC_VERSION, 0, 0, 0);

    if ret.error != 0 {
        return Err(SbiError::from(ret.error));
    }

    let minor = (ret.value & 0xFFFFFF) as u32;
    let major = ((ret.value >> 24) & 0x7F) as u32;

    Ok((major, minor))
}

pub fn impl_id() -> Result<usize, SbiError> {
    let ret = sbi_call(EID_BASE, FID_GET_IMPL_ID, 0, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(ret.value)
    }
}

pub fn impl_version() -> Result<usize, SbiError> {
    let ret = sbi_call(EID_BASE, FID_GET_IMPL_VERSION, 0, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(ret.value)
    }
}

pub fn probe_extension_base(eid: usize) -> Result<bool, SbiError> {
    let ret = sbi_call(EID_BASE, FID_PROBE_EXTENSION, eid, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(ret.value != 0)
    }
}

pub fn mvendorid() -> Result<usize, SbiError> {
    let ret = sbi_call(EID_BASE, FID_GET_MVENDORID, 0, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(ret.value)
    }
}

pub fn marchid() -> Result<usize, SbiError> {
    let ret = sbi_call(EID_BASE, FID_GET_MARCHID, 0, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(ret.value)
    }
}

pub fn mimpid() -> Result<usize, SbiError> {
    let ret = sbi_call(EID_BASE, FID_GET_MIMPID, 0, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(ret.value)
    }
}

pub fn impl_name(id: usize) -> &'static str {
    match id {
        0 => "Berkeley Boot Loader (BBL)",
        1 => "OpenSBI",
        2 => "Xvisor",
        3 => "KVM",
        4 => "RustSBI",
        5 => "Diosix",
        6 => "Coffer",
        _ => "Unknown",
    }
}
