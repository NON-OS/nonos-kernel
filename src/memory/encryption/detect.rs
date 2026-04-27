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

use super::types::EncryptionCapability;

const CPUID_AMD_SME_LEAF: u32 = 0x8000001F;
const CPUID_INTEL_TME_LEAF: u32 = 0x13;

pub fn detect_encryption_support() -> EncryptionCapability {
    let mut cap = EncryptionCapability::none();
    if is_amd_cpu() {
        detect_amd_encryption(&mut cap);
    } else if is_intel_cpu() {
        detect_intel_encryption(&mut cap);
    }
    cap
}

fn is_amd_cpu() -> bool {
    let (_, ebx, ecx, edx) = cpuid(0);
    ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163
}

fn is_intel_cpu() -> bool {
    let (_, ebx, ecx, edx) = cpuid(0);
    ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E
}

fn detect_amd_encryption(cap: &mut EncryptionCapability) {
    let (max_ext, _, _, _) = cpuid(0x80000000);
    if max_ext < CPUID_AMD_SME_LEAF {
        return;
    }
    let (eax, ebx, _, _) = cpuid(CPUID_AMD_SME_LEAF);
    cap.sme_supported = (eax & 0x01) != 0;
    cap.sev_supported = (eax & 0x02) != 0;
    cap.c_bit_position = (ebx & 0x3F) as u8;
    cap.phys_addr_reduction = ((ebx >> 6) & 0x3F) as u8;
}

fn detect_intel_encryption(cap: &mut EncryptionCapability) {
    let (max_leaf, _, _, _) = cpuid(0);
    if max_leaf < 7 {
        return;
    }
    let (_, _, ecx, _) = cpuid_subleaf(7, 0);
    cap.tme_supported = (ecx & (1 << 13)) != 0;
    cap.mktme_supported = cap.tme_supported && max_leaf >= CPUID_INTEL_TME_LEAF;
    if cap.mktme_supported {
        let (eax, _, _, _) = cpuid_subleaf(CPUID_INTEL_TME_LEAF, 0);
        cap.keyid_bits = ((eax >> 4) & 0x0F) as u8;
    }
}

pub fn get_encryption_mask(cap: &EncryptionCapability) -> u64 {
    if cap.c_bit_position > 0 {
        1u64 << cap.c_bit_position
    } else {
        0
    }
}

fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    crate::arch::x86_64::cpu::cpuid::cpuid(leaf)
}

fn cpuid_subleaf(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    crate::arch::x86_64::cpu::cpuid::cpuid_count(leaf, subleaf)
}
