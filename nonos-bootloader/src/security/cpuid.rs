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

#[cfg(target_arch = "x86_64")]
pub fn cpu_rng_supported() -> bool {
    unsafe {
        let (_, _, ecx, _) = cpuid(1);
        let rdrand = (ecx & (1 << 30)) != 0;
        let (_, ebx, _, _) = cpuid(7);
        let rdseed = (ebx & (1 << 18)) != 0;
        rdrand || rdseed
    }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx_out:e}, ebx",
        "pop rbx",
        inout("eax") leaf => eax,
        ebx_out = out(reg) ebx,
        out("ecx") ecx,
        out("edx") edx,
        options(nostack, preserves_flags)
    );

    (eax, ebx, ecx, edx)
}
