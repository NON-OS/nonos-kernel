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

pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "push rbx", "cpuid", "mov {0:e}, ebx", "pop rbx",
            out(reg) ebx, inout("eax") leaf => eax, inout("ecx") subleaf => ecx, out("edx") edx, options(preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

pub fn cpuid_max_leaf() -> u32 { cpuid(0, 0).0 }

pub fn cpuid_max_extended_leaf() -> u32 { cpuid(0x80000000, 0).0 }
