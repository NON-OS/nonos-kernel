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

use super::constants::{
    CR0_PG, CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_OSXSAVE, CR4_PAE, EFER_LMA, MSR_EFER,
    XCR0_AVX, XCR0_HI16_ZMM, XCR0_OPMASK, XCR0_SSE, XCR0_X87, XCR0_ZMM_HI256,
};
use super::cpu_ops::{read_cr0, read_cr3, read_cr4, read_xcr0, rdmsr, write_cr0, write_cr4, write_xcr0};
use super::error::BootError;

use crate::arch::x86_64::cpu;

pub unsafe fn validate_memory() -> Result<(), BootError> {
    let cr3 = read_cr3();
    if cr3 == 0 {
        return Err(BootError::InvalidPageTable);
    }

    let cr0 = read_cr0();
    if cr0 & CR0_PG == 0 {
        return Err(BootError::PagingNotEnabled);
    }

    let cr4 = read_cr4();
    if cr4 & CR4_PAE == 0 {
        return Err(BootError::PaeNotEnabled);
    }

    let efer = rdmsr(MSR_EFER);
    if efer & EFER_LMA == 0 {
        return Err(BootError::LongModeNotActive);
    }

    Ok(())
}

pub fn validate_cpu_features() -> Result<(), BootError> {
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

    if !features.apic {
        return Err(BootError::NoApic);
    }

    if !features.msr {
        return Err(BootError::NoMsr);
    }

    Ok(())
}

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

pub fn get_simd_support() -> SimdSupport {
    let features = cpu::features();

    SimdSupport {
        sse: features.sse,
        sse2: features.sse2,
        sse3: features.sse3,
        ssse3: features.ssse3,
        sse4_1: features.sse4_1,
        sse4_2: features.sse4_2,
        avx: features.avx,
        avx2: features.avx2,
        avx512f: features.avx512f,
        fma: features.fma,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SimdSupport {
    pub sse: bool,
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub fma: bool,
}

impl SimdSupport {
    pub fn highest_level(&self) -> SimdLevel {
        if self.avx512f {
            SimdLevel::Avx512
        } else if self.avx2 {
            SimdLevel::Avx2
        } else if self.avx {
            SimdLevel::Avx
        } else if self.sse4_2 {
            SimdLevel::Sse42
        } else if self.sse4_1 {
            SimdLevel::Sse41
        } else if self.ssse3 {
            SimdLevel::Ssse3
        } else if self.sse3 {
            SimdLevel::Sse3
        } else if self.sse2 {
            SimdLevel::Sse2
        } else if self.sse {
            SimdLevel::Sse
        } else {
            SimdLevel::None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimdLevel {
    None = 0,
    Sse = 1,
    Sse2 = 2,
    Sse3 = 3,
    Ssse3 = 4,
    Sse41 = 5,
    Sse42 = 6,
    Avx = 7,
    Avx2 = 8,
    Avx512 = 9,
}

impl SimdLevel {
    pub const fn register_width(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Sse | Self::Sse2 | Self::Sse3 | Self::Ssse3 | Self::Sse41 | Self::Sse42 => 128,
            Self::Avx | Self::Avx2 => 256,
            Self::Avx512 => 512,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_level_ordering() {
        assert!(SimdLevel::Avx512 > SimdLevel::Avx2);
        assert!(SimdLevel::Avx2 > SimdLevel::Avx);
        assert!(SimdLevel::Sse2 > SimdLevel::Sse);
    }

    #[test]
    fn test_register_width() {
        assert_eq!(SimdLevel::Sse.register_width(), 128);
        assert_eq!(SimdLevel::Avx.register_width(), 256);
        assert_eq!(SimdLevel::Avx512.register_width(), 512);
    }

    #[test]
    fn test_simd_support_highest_level() {
        let support = SimdSupport {
            sse: true,
            sse2: true,
            avx: true,
            ..Default::default()
        };
        assert_eq!(support.highest_level(), SimdLevel::Avx);
    }
}
