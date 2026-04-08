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

pub fn detect_leaf7_ebx(features: &mut CpuFeatures, ebx: u32) {
    features.fsgsbase = ebx & (1 << 0) != 0; features.tsc_adjust = ebx & (1 << 1) != 0;
    features.sgx = ebx & (1 << 2) != 0; features.bmi1 = ebx & (1 << 3) != 0;
    features.hle = ebx & (1 << 4) != 0; features.avx2 = ebx & (1 << 5) != 0;
    features.smep = ebx & (1 << 7) != 0; features.bmi2 = ebx & (1 << 8) != 0;
    features.erms = ebx & (1 << 9) != 0; features.invpcid = ebx & (1 << 10) != 0;
    features.rtm = ebx & (1 << 11) != 0; features.pqm = ebx & (1 << 12) != 0;
    features.mpx = ebx & (1 << 14) != 0; features.pqe = ebx & (1 << 15) != 0;
    features.avx512f = ebx & (1 << 16) != 0; features.avx512dq = ebx & (1 << 17) != 0;
    features.rdseed = ebx & (1 << 18) != 0; features.adx = ebx & (1 << 19) != 0;
    features.smap = ebx & (1 << 20) != 0; features.avx512ifma = ebx & (1 << 21) != 0;
    features.clflushopt = ebx & (1 << 23) != 0; features.clwb = ebx & (1 << 24) != 0;
    features.avx512pf = ebx & (1 << 26) != 0; features.avx512er = ebx & (1 << 27) != 0;
    features.avx512cd = ebx & (1 << 28) != 0; features.sha = ebx & (1 << 29) != 0;
    features.avx512bw = ebx & (1 << 30) != 0; features.avx512vl = ebx & (1u32 << 31) != 0;
}

pub fn detect_leaf7_ecx(features: &mut CpuFeatures, ecx: u32) {
    features.prefetchwt1 = ecx & (1 << 0) != 0; features.avx512vbmi = ecx & (1 << 1) != 0;
    features.umip = ecx & (1 << 2) != 0; features.pku = ecx & (1 << 3) != 0;
    features.ospke = ecx & (1 << 4) != 0; features.avx512vbmi2 = ecx & (1 << 6) != 0;
    features.cet_ss = ecx & (1 << 7) != 0; features.gfni = ecx & (1 << 8) != 0;
    features.vaes = ecx & (1 << 9) != 0; features.vpclmulqdq = ecx & (1 << 10) != 0;
    features.avx512vnni = ecx & (1 << 11) != 0; features.avx512bitalg = ecx & (1 << 12) != 0;
    features.avx512vpopcntdq = ecx & (1 << 14) != 0; features.la57 = ecx & (1 << 16) != 0;
    features.rdpid = ecx & (1 << 22) != 0;
}

pub fn detect_leaf7_edx(features: &mut CpuFeatures, edx: u32) {
    features.avx512_4vnniw = edx & (1 << 2) != 0; features.avx512_4fmaps = edx & (1 << 3) != 0;
    features.fsrm = edx & (1 << 4) != 0; features.avx512vp2intersect = edx & (1 << 8) != 0;
    features.md_clear = edx & (1 << 10) != 0; features.tsx_force_abort = edx & (1 << 13) != 0;
    features.serialize = edx & (1 << 14) != 0; features.hybrid = edx & (1 << 15) != 0;
    features.cet_ibt = edx & (1 << 20) != 0; features.spec_ctrl = edx & (1 << 26) != 0;
    features.stibp = edx & (1 << 27) != 0; features.flush_cmd = edx & (1 << 28) != 0;
    features.arch_cap = edx & (1 << 29) != 0; features.ssbd = edx & (1u32 << 31) != 0;
}
