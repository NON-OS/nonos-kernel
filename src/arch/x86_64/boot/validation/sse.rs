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
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_OSXSAVE,
    XCR0_AVX, XCR0_HI16_ZMM, XCR0_OPMASK, XCR0_SSE, XCR0_X87, XCR0_ZMM_HI256,
};
use super::super::cpu_ops::{read_cr0, read_cr4, read_xcr0, write_cr0, write_cr4, write_xcr0};
use super::super::error::BootError;
use crate::arch::x86_64::cpu;

pub unsafe fn enable_sse() -> Result<(), BootError> {
    let features = cpu::features();

    if !features.sse {
        return Err(BootError::NoSse);
    }
    if !features.sse2 {
        return Err(BootError::NoSse2);
    }
    if !features.fxsr {
        return Err(BootError::NoFxsr);
    }

    let mut cr0 = read_cr0();
    cr0 &= !(1 << 2);
    cr0 |= 1 << 1;
    write_cr0(cr0);

    let mut cr4 = read_cr4();
    cr4 |= CR4_OSFXSR;
    cr4 |= CR4_OSXMMEXCPT;

    if features.xsave {
        cr4 |= CR4_OSXSAVE;
    }

    write_cr4(cr4);

    Ok(())
}

pub unsafe fn enable_avx() -> Result<(), BootError> {
    let features = cpu::features();

    if !features.avx || !features.xsave {
        return Ok(());
    }

    let cr4 = read_cr4();
    if cr4 & CR4_OSXSAVE == 0 {
        return Ok(());
    }

    let xcr0 = XCR0_X87 | XCR0_SSE | XCR0_AVX;
    write_xcr0(xcr0);

    Ok(())
}

pub unsafe fn enable_avx512() -> Result<(), BootError> {
    let features = cpu::features();

    if !features.avx512f || !features.xsave {
        return Ok(());
    }

    let cr4 = read_cr4();
    if cr4 & CR4_OSXSAVE == 0 {
        return Ok(());
    }

    let current_xcr0 = read_xcr0();
    if current_xcr0 & XCR0_AVX == 0 {
        return Ok(());
    }

    let xcr0 = current_xcr0 | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;
    write_xcr0(xcr0);

    Ok(())
}

pub unsafe fn enable_sse_avx() -> Result<(), BootError> {
    enable_sse()?;
    enable_avx()?;
    enable_avx512()?;
    Ok(())
}
