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

use crate::arch::x86_64::cpu::cpuid::{cpuid, cpuid_count, cpuid_max_leaf, cpuid_max_extended_leaf};
use super::types::CpuFeatures;

impl CpuFeatures {
    pub fn detect() -> Self {
        let mut features = Self::new();
        let (_, _, ecx, edx) = cpuid(1);

        features.sse3 = ecx & (1 << 0) != 0;
        features.pclmulqdq = ecx & (1 << 1) != 0;
        features.dtes64 = ecx & (1 << 2) != 0;
        features.monitor = ecx & (1 << 3) != 0;
        features.ds_cpl = ecx & (1 << 4) != 0;
        features.vmx = ecx & (1 << 5) != 0;
        features.smx = ecx & (1 << 6) != 0;
        features.est = ecx & (1 << 7) != 0;
        features.tm2 = ecx & (1 << 8) != 0;
        features.ssse3 = ecx & (1 << 9) != 0;
        features.cnxt_id = ecx & (1 << 10) != 0;
        features.fma = ecx & (1 << 12) != 0;
        features.cx16 = ecx & (1 << 13) != 0;
        features.xtpr = ecx & (1 << 14) != 0;
        features.pdcm = ecx & (1 << 15) != 0;
        features.pcid = ecx & (1 << 17) != 0;
        features.dca = ecx & (1 << 18) != 0;
        features.sse4_1 = ecx & (1 << 19) != 0;
        features.sse4_2 = ecx & (1 << 20) != 0;
        features.x2apic = ecx & (1 << 21) != 0;
        features.movbe = ecx & (1 << 22) != 0;
        features.popcnt = ecx & (1 << 23) != 0;
        features.tsc_deadline = ecx & (1 << 24) != 0;
        features.aes_ni = ecx & (1 << 25) != 0;
        features.xsave = ecx & (1 << 26) != 0;
        features.osxsave = ecx & (1 << 27) != 0;
        features.avx = ecx & (1 << 28) != 0;
        features.f16c = ecx & (1 << 29) != 0;
        features.rdrand = ecx & (1 << 30) != 0;
        features.hypervisor = ecx & (1 << 31) != 0;

        features.fpu = edx & (1 << 0) != 0;
        features.vme = edx & (1 << 1) != 0;
        features.de = edx & (1 << 2) != 0;
        features.pse = edx & (1 << 3) != 0;
        features.tsc = edx & (1 << 4) != 0;
        features.msr = edx & (1 << 5) != 0;
        features.pae = edx & (1 << 6) != 0;
        features.mce = edx & (1 << 7) != 0;
        features.cx8 = edx & (1 << 8) != 0;
        features.apic = edx & (1 << 9) != 0;
        features.sep = edx & (1 << 11) != 0;
        features.mtrr = edx & (1 << 12) != 0;
        features.pge = edx & (1 << 13) != 0;
        features.mca = edx & (1 << 14) != 0;
        features.cmov = edx & (1 << 15) != 0;
        features.pat = edx & (1 << 16) != 0;
        features.pse36 = edx & (1 << 17) != 0;
        features.psn = edx & (1 << 18) != 0;
        features.clflush = edx & (1 << 19) != 0;
        features.ds = edx & (1 << 21) != 0;
        features.acpi = edx & (1 << 22) != 0;
        features.mmx = edx & (1 << 23) != 0;
        features.fxsr = edx & (1 << 24) != 0;
        features.sse = edx & (1 << 25) != 0;
        features.sse2 = edx & (1 << 26) != 0;
        features.ss = edx & (1 << 27) != 0;
        features.htt = edx & (1 << 28) != 0;
        features.tm = edx & (1 << 29) != 0;
        features.ia64 = edx & (1 << 30) != 0;
        features.pbe = edx & (1u32 << 31) != 0;

        let max_leaf = cpuid_max_leaf();
        if max_leaf >= 7 {
            let (_, ebx, ecx, edx) = cpuid_count(7, 0);

            features.fsgsbase = ebx & (1 << 0) != 0;
            features.tsc_adjust = ebx & (1 << 1) != 0;
            features.sgx = ebx & (1 << 2) != 0;
            features.bmi1 = ebx & (1 << 3) != 0;
            features.hle = ebx & (1 << 4) != 0;
            features.avx2 = ebx & (1 << 5) != 0;
            features.smep = ebx & (1 << 7) != 0;
            features.bmi2 = ebx & (1 << 8) != 0;
            features.erms = ebx & (1 << 9) != 0;
            features.invpcid = ebx & (1 << 10) != 0;
            features.rtm = ebx & (1 << 11) != 0;
            features.pqm = ebx & (1 << 12) != 0;
            features.mpx = ebx & (1 << 14) != 0;
            features.pqe = ebx & (1 << 15) != 0;
            features.avx512f = ebx & (1 << 16) != 0;
            features.avx512dq = ebx & (1 << 17) != 0;
            features.rdseed = ebx & (1 << 18) != 0;
            features.adx = ebx & (1 << 19) != 0;
            features.smap = ebx & (1 << 20) != 0;
            features.avx512ifma = ebx & (1 << 21) != 0;
            features.clflushopt = ebx & (1 << 23) != 0;
            features.clwb = ebx & (1 << 24) != 0;
            features.avx512pf = ebx & (1 << 26) != 0;
            features.avx512er = ebx & (1 << 27) != 0;
            features.avx512cd = ebx & (1 << 28) != 0;
            features.sha = ebx & (1 << 29) != 0;
            features.avx512bw = ebx & (1 << 30) != 0;
            features.avx512vl = ebx & (1u32 << 31) != 0;

            features.prefetchwt1 = ecx & (1 << 0) != 0;
            features.avx512vbmi = ecx & (1 << 1) != 0;
            features.umip = ecx & (1 << 2) != 0;
            features.pku = ecx & (1 << 3) != 0;
            features.ospke = ecx & (1 << 4) != 0;
            features.avx512vbmi2 = ecx & (1 << 6) != 0;
            features.cet_ss = ecx & (1 << 7) != 0;
            features.gfni = ecx & (1 << 8) != 0;
            features.vaes = ecx & (1 << 9) != 0;
            features.vpclmulqdq = ecx & (1 << 10) != 0;
            features.avx512vnni = ecx & (1 << 11) != 0;
            features.avx512bitalg = ecx & (1 << 12) != 0;
            features.avx512vpopcntdq = ecx & (1 << 14) != 0;
            features.la57 = ecx & (1 << 16) != 0;
            features.rdpid = ecx & (1 << 22) != 0;

            features.avx512_4vnniw = edx & (1 << 2) != 0;
            features.avx512_4fmaps = edx & (1 << 3) != 0;
            features.fsrm = edx & (1 << 4) != 0;
            features.avx512vp2intersect = edx & (1 << 8) != 0;
            features.md_clear = edx & (1 << 10) != 0;
            features.serialize = edx & (1 << 14) != 0;
            features.hybrid = edx & (1 << 15) != 0;
            features.tsx_force_abort = edx & (1 << 13) != 0;
            features.cet_ibt = edx & (1 << 20) != 0;
            features.spec_ctrl = edx & (1 << 26) != 0;
            features.stibp = edx & (1 << 27) != 0;
            features.flush_cmd = edx & (1 << 28) != 0;
            features.arch_cap = edx & (1 << 29) != 0;
            features.ssbd = edx & (1u32 << 31) != 0;
        }

        let max_ext = cpuid_max_extended_leaf();
        if max_ext >= 0x80000001 {
            let (_, _, ecx, edx) = cpuid(0x80000001);

            features.lahf_lm = ecx & (1 << 0) != 0;
            features.cmp_legacy = ecx & (1 << 1) != 0;
            features.svm = ecx & (1 << 2) != 0;
            features.extapic = ecx & (1 << 3) != 0;
            features.cr8_legacy = ecx & (1 << 4) != 0;
            features.abm = ecx & (1 << 5) != 0;
            features.sse4a = ecx & (1 << 6) != 0;
            features.misalignsse = ecx & (1 << 7) != 0;
            features.prefetch3d = ecx & (1 << 8) != 0;
            features.osvw = ecx & (1 << 9) != 0;
            features.ibs = ecx & (1 << 10) != 0;
            features.xop = ecx & (1 << 11) != 0;
            features.skinit = ecx & (1 << 12) != 0;
            features.wdt = ecx & (1 << 13) != 0;
            features.lwp = ecx & (1 << 15) != 0;
            features.fma4 = ecx & (1 << 16) != 0;
            features.tce = ecx & (1 << 17) != 0;
            features.tbm = ecx & (1 << 21) != 0;
            features.topology = ecx & (1 << 22) != 0;
            features.perfctr_core = ecx & (1 << 23) != 0;
            features.perfctr_nb = ecx & (1 << 24) != 0;
            features.dbx = ecx & (1 << 26) != 0;
            features.perftsc = ecx & (1 << 27) != 0;
            features.pcx_l2i = ecx & (1 << 28) != 0;

            features.syscall = edx & (1 << 11) != 0;
            features.mp = edx & (1 << 19) != 0;
            features.nx = edx & (1 << 20) != 0;
            features.mmxext = edx & (1 << 22) != 0;
            features.fxsr_opt = edx & (1 << 25) != 0;
            features.pdpe1gb = edx & (1 << 26) != 0;
            features.rdtscp = edx & (1 << 27) != 0;
            features.lm = edx & (1 << 29) != 0;
            features._3dnowext = edx & (1 << 30) != 0;
            features._3dnow = edx & (1u32 << 31) != 0;
        }

        features
    }
}
