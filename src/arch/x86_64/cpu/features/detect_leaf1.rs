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

use super::types::CpuFeatures;

pub fn detect_leaf1_ecx(features: &mut CpuFeatures, ecx: u32) {
    features.sse3 = ecx & (1 << 0) != 0; features.pclmulqdq = ecx & (1 << 1) != 0;
    features.dtes64 = ecx & (1 << 2) != 0; features.monitor = ecx & (1 << 3) != 0;
    features.ds_cpl = ecx & (1 << 4) != 0; features.vmx = ecx & (1 << 5) != 0;
    features.smx = ecx & (1 << 6) != 0; features.est = ecx & (1 << 7) != 0;
    features.tm2 = ecx & (1 << 8) != 0; features.ssse3 = ecx & (1 << 9) != 0;
    features.cnxt_id = ecx & (1 << 10) != 0; features.fma = ecx & (1 << 12) != 0;
    features.cx16 = ecx & (1 << 13) != 0; features.xtpr = ecx & (1 << 14) != 0;
    features.pdcm = ecx & (1 << 15) != 0; features.pcid = ecx & (1 << 17) != 0;
    features.dca = ecx & (1 << 18) != 0; features.sse4_1 = ecx & (1 << 19) != 0;
    features.sse4_2 = ecx & (1 << 20) != 0; features.x2apic = ecx & (1 << 21) != 0;
    features.movbe = ecx & (1 << 22) != 0; features.popcnt = ecx & (1 << 23) != 0;
    features.tsc_deadline = ecx & (1 << 24) != 0; features.aes_ni = ecx & (1 << 25) != 0;
    features.xsave = ecx & (1 << 26) != 0; features.osxsave = ecx & (1 << 27) != 0;
    features.avx = ecx & (1 << 28) != 0; features.f16c = ecx & (1 << 29) != 0;
    features.rdrand = ecx & (1 << 30) != 0; features.hypervisor = ecx & (1 << 31) != 0;
}

pub fn detect_leaf1_edx(features: &mut CpuFeatures, edx: u32) {
    features.fpu = edx & (1 << 0) != 0; features.vme = edx & (1 << 1) != 0;
    features.de = edx & (1 << 2) != 0; features.pse = edx & (1 << 3) != 0;
    features.tsc = edx & (1 << 4) != 0; features.msr = edx & (1 << 5) != 0;
    features.pae = edx & (1 << 6) != 0; features.mce = edx & (1 << 7) != 0;
    features.cx8 = edx & (1 << 8) != 0; features.apic = edx & (1 << 9) != 0;
    features.sep = edx & (1 << 11) != 0; features.mtrr = edx & (1 << 12) != 0;
    features.pge = edx & (1 << 13) != 0; features.mca = edx & (1 << 14) != 0;
    features.cmov = edx & (1 << 15) != 0; features.pat = edx & (1 << 16) != 0;
    features.pse36 = edx & (1 << 17) != 0; features.psn = edx & (1 << 18) != 0;
    features.clflush = edx & (1 << 19) != 0; features.ds = edx & (1 << 21) != 0;
    features.acpi = edx & (1 << 22) != 0; features.mmx = edx & (1 << 23) != 0;
    features.fxsr = edx & (1 << 24) != 0; features.sse = edx & (1 << 25) != 0;
    features.sse2 = edx & (1 << 26) != 0; features.ss = edx & (1 << 27) != 0;
    features.htt = edx & (1 << 28) != 0; features.tm = edx & (1 << 29) != 0;
    features.ia64 = edx & (1 << 30) != 0; features.pbe = edx & (1u32 << 31) != 0;
}
