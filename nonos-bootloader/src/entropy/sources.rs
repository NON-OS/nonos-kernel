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

#[inline(always)]
pub fn rdtsc_serialized() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("lfence", options(nostack, nomem));

        let mut hi: u32;
        let mut lo: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );

        core::arch::asm!("lfence", options(nostack, nomem));

        ((hi as u64) << 32) | (lo as u64)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[inline]
fn has_rdseed() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ebx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            ebx = out(reg) ebx,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack)
        );
        (ebx & (1 << 18)) != 0 // RDSEED bit
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

#[inline(always)]
pub fn rdseed64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if !has_rdseed() {
            return None;
        }
        unsafe {
            let mut x: u64 = 0;
            let ok = core::arch::x86_64::_rdseed64_step(&mut x);
            if ok == 1 {
                Some(x)
            } else {
                None
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

#[inline]
fn has_rdrand() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ecx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "mov {ecx:e}, ecx",
            "pop rbx",
            ecx = out(reg) ecx,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack)
        );
        (ecx & (1 << 30)) != 0 // RDRAND bit
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

#[inline(always)]
pub fn rdrand64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if !has_rdrand() {
            return None;
        }
        unsafe {
            let mut x: u64;
            let ok: u8;
            core::arch::asm!(
                "rdrand {x}",
                "setc {ok}",
                x = out(reg) x,
                ok = out(reg_byte) ok,
                options(nostack, nomem)
            );
            if ok != 0 {
                Some(x)
            } else {
                None
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

pub fn collect_hw_rng_bytes(buf: &mut [u8; 64], iterations: usize) {
    let mut off = 0usize;

    for i in 0..iterations {
        if let Some(x) = rdseed64() {
            let b = x.to_le_bytes();
            for j in 0..8 { buf[(off + j) % 64] ^= b[j]; }
            off += 8;
        } else {
            for _ in 0..10 {
                if let Some(x) = rdrand64() {
                    let b = x.to_le_bytes();
                    for j in 0..8 { buf[(off + j) % 64] ^= b[j]; }
                    off += 8;
                    break;
                }
                for _ in 0..50 { core::hint::spin_loop(); }
            }
        }
        let t1 = rdtsc_serialized();
        for _ in 0..((i % 16) + 1) { core::hint::spin_loop(); }
        let t2 = rdtsc_serialized();
        let jb = t2.wrapping_sub(t1).to_le_bytes();
        for j in 0..8 { buf[(off + j + 32) % 64] ^= jb[j]; }
    }

    for i in 0..64 {
        let t = rdtsc_serialized();
        for _ in 0..((i % 8) + 1) { core::hint::spin_loop(); }
        buf[i] ^= (t >> ((i % 8) * 8)) as u8;
    }
}
