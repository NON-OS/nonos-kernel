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

pub(super) fn has_ibrs_ibpb() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    (result.edx & (1 << 26)) != 0
}

pub(super) fn has_stibp() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    (result.edx & (1 << 27)) != 0
}

pub(super) fn has_ssbd() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    (result.edx & (1 << 31)) != 0
}

pub(super) fn has_l1d_flush() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    (result.edx & (1 << 28)) != 0
}

pub(super) fn has_md_clear() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    (result.edx & (1 << 10)) != 0
}

pub(super) fn has_tsx() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    let rtm = (result.ebx & (1 << 11)) != 0;
    let hle = (result.ebx & (1 << 4)) != 0;
    rtm || hle
}

pub(super) fn has_arch_capabilities() -> bool {
    let result = core::arch::x86_64::__cpuid_count(7, 0);
    (result.edx & (1 << 29)) != 0
}

pub(super) fn vendor() -> [u8; 12] {
    let result = core::arch::x86_64::__cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&result.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&result.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&result.ecx.to_le_bytes());
    vendor
}

pub(super) fn is_intel() -> bool {
    vendor() == *b"GenuineIntel"
}

pub(super) fn is_amd() -> bool {
    vendor() == *b"AuthenticAMD"
}
