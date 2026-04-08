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

use super::super::constants::{
    CR4_OSXSAVE, XCR0_AVX, XCR0_HI16_ZMM, XCR0_OPMASK, XCR0_SSE, XCR0_X87, XCR0_ZMM_HI256,
};
use super::super::cpu_ops::{read_cr4, read_xcr0, write_xcr0};
use super::super::error::BootError;
use super::sse_enable::enable_sse;
use crate::arch::x86_64::cpu;

pub unsafe fn enable_avx() -> Result<(), BootError> {
    let features = cpu::features();
    if !features.avx || !features.xsave { return Ok(()); }
    let cr4 = read_cr4();
    if cr4 & CR4_OSXSAVE == 0 { return Ok(()); }
    write_xcr0(XCR0_X87 | XCR0_SSE | XCR0_AVX);
    Ok(())
}

pub unsafe fn enable_avx512() -> Result<(), BootError> {
    let features = cpu::features();
    if !features.avx512f || !features.xsave { return Ok(()); }
    let cr4 = read_cr4();
    if cr4 & CR4_OSXSAVE == 0 { return Ok(()); }
    let current_xcr0 = read_xcr0();
    if current_xcr0 & XCR0_AVX == 0 { return Ok(()); }
    write_xcr0(current_xcr0 | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM);
    Ok(())
}

pub unsafe fn enable_sse_avx() -> Result<(), BootError> {
    enable_sse()?;
    enable_avx()?;
    enable_avx512()?;
    Ok(())
}
