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
pub unsafe fn cpuid_leaf_7() -> (u32, u32, u32) {
    let (ebx, ecx, edx): (u32, u32, u32);
    core::arch::asm!("push rbx", "cpuid", "mov {ebx_out:e}, ebx", "pop rbx", in("eax") 7u32, in("ecx") 0u32, ebx_out = out(reg) ebx, lateout("ecx") ecx, lateout("edx") edx, options(preserves_flags));
    (ebx, ecx, edx)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn cpuid_leaf_1() -> (u32, u32) {
    let (ecx, edx): (u32, u32);
    core::arch::asm!("push rbx", "cpuid", "pop rbx", in("eax") 1u32, lateout("ecx") ecx, lateout("edx") edx, lateout("eax") _, options(preserves_flags));
    (ecx, edx)
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn cpuid_extended_leaf() -> u32 {
    let edx: u32;
    core::arch::asm!("push rbx", "cpuid", "pop rbx", in("eax") 0x80000001u32, lateout("edx") edx, lateout("eax") _, lateout("ecx") _, options(preserves_flags));
    edx
}
