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

use super::cpuid::{cpuid, cpuid_count, cpuid_max_leaf, cpuid_max_extended_leaf};

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub sse3: bool,
    pub pclmulqdq: bool,
    pub dtes64: bool,
    pub monitor: bool,
    pub ds_cpl: bool,
    pub vmx: bool,
    pub smx: bool,
    pub est: bool,
    pub tm2: bool,
    pub ssse3: bool,
    pub cnxt_id: bool,
    pub fma: bool,
    pub cx16: bool,
    pub xtpr: bool,
    pub pdcm: bool,
    pub pcid: bool,
    pub dca: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub x2apic: bool,
    pub movbe: bool,
    pub popcnt: bool,
    pub tsc_deadline: bool,
    pub aes_ni: bool,
    pub xsave: bool,
    pub osxsave: bool,
    pub avx: bool,
    pub f16c: bool,
    pub rdrand: bool,
    pub hypervisor: bool,
    pub fpu: bool,
    pub vme: bool,
    pub de: bool,
    pub pse: bool,
    pub tsc: bool,
    pub msr: bool,
    pub pae: bool,
    pub mce: bool,
    pub cx8: bool,
    pub apic: bool,
    pub sep: bool,
    pub mtrr: bool,
    pub pge: bool,
    pub mca: bool,
    pub cmov: bool,
    pub pat: bool,
    pub pse36: bool,
    pub psn: bool,
    pub clflush: bool,
    pub ds: bool,
    pub acpi: bool,
    pub mmx: bool,
    pub fxsr: bool,
    pub sse: bool,
    pub sse2: bool,
    pub ss: bool,
    pub htt: bool,
    pub tm: bool,
    pub ia64: bool,
    pub pbe: bool,
    pub fsgsbase: bool,
    pub tsc_adjust: bool,
    pub sgx: bool,
    pub bmi1: bool,
    pub hle: bool,
    pub avx2: bool,
    pub smep: bool,
    pub bmi2: bool,
    pub erms: bool,
    pub invpcid: bool,
    pub rtm: bool,
    pub pqm: bool,
    pub mpx: bool,
    pub pqe: bool,
    pub avx512f: bool,
    pub avx512dq: bool,
    pub rdseed: bool,
    pub adx: bool,
    pub smap: bool,
    pub avx512ifma: bool,
    pub clflushopt: bool,
    pub clwb: bool,
    pub avx512pf: bool,
    pub avx512er: bool,
    pub avx512cd: bool,
    pub sha: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
    pub prefetchwt1: bool,
    pub avx512vbmi: bool,
    pub umip: bool,
    pub pku: bool,
    pub ospke: bool,
    pub avx512vbmi2: bool,
    pub cet_ss: bool,
    pub gfni: bool,
    pub vaes: bool,
    pub vpclmulqdq: bool,
    pub avx512vnni: bool,
    pub avx512bitalg: bool,
    pub avx512vpopcntdq: bool,
    pub la57: bool,
    pub rdpid: bool,
    pub avx512_4vnniw: bool,
    pub avx512_4fmaps: bool,
    pub fsrm: bool,
    pub avx512vp2intersect: bool,
    pub md_clear: bool,
    pub serialize: bool,
    pub hybrid: bool,
    pub tsx_force_abort: bool,
    pub cet_ibt: bool,
    pub spec_ctrl: bool,
    pub stibp: bool,
    pub flush_cmd: bool,
    pub arch_cap: bool,
    pub ssbd: bool,
    pub lahf_lm: bool,
    pub cmp_legacy: bool,
    pub svm: bool,
    pub extapic: bool,
    pub cr8_legacy: bool,
    pub abm: bool,
    pub sse4a: bool,
    pub misalignsse: bool,
    pub prefetch3d: bool,
    pub osvw: bool,
    pub ibs: bool,
    pub xop: bool,
    pub skinit: bool,
    pub wdt: bool,
    pub lwp: bool,
    pub fma4: bool,
    pub tce: bool,
    pub tbm: bool,
    pub topology: bool,
    pub perfctr_core: bool,
    pub perfctr_nb: bool,
    pub dbx: bool,
    pub perftsc: bool,
    pub pcx_l2i: bool,
    pub syscall: bool,
    pub mp: bool,
    pub nx: bool,
    pub mmxext: bool,
    pub fxsr_opt: bool,
    pub pdpe1gb: bool,
    pub rdtscp: bool,
    pub lm: bool,
    pub _3dnowext: bool,
    pub _3dnow: bool,
}

impl CpuFeatures {
    pub const fn new() -> Self {
        Self {
            sse3: false, pclmulqdq: false, dtes64: false, monitor: false, ds_cpl: false,
            vmx: false, smx: false, est: false, tm2: false, ssse3: false, cnxt_id: false,
            fma: false, cx16: false, xtpr: false, pdcm: false, pcid: false, dca: false,
            sse4_1: false, sse4_2: false, x2apic: false, movbe: false, popcnt: false,
            tsc_deadline: false, aes_ni: false, xsave: false, osxsave: false, avx: false,
            f16c: false, rdrand: false, hypervisor: false,
            fpu: false, vme: false, de: false, pse: false, tsc: false, msr: false,
            pae: false, mce: false, cx8: false, apic: false, sep: false, mtrr: false,
            pge: false, mca: false, cmov: false, pat: false, pse36: false, psn: false,
            clflush: false, ds: false, acpi: false, mmx: false, fxsr: false, sse: false,
            sse2: false, ss: false, htt: false, tm: false, ia64: false, pbe: false,
            fsgsbase: false, tsc_adjust: false, sgx: false, bmi1: false, hle: false,
            avx2: false, smep: false, bmi2: false, erms: false, invpcid: false, rtm: false,
            pqm: false, mpx: false, pqe: false, avx512f: false, avx512dq: false, rdseed: false,
            adx: false, smap: false, avx512ifma: false, clflushopt: false, clwb: false,
            avx512pf: false, avx512er: false, avx512cd: false, sha: false, avx512bw: false,
            avx512vl: false, prefetchwt1: false, avx512vbmi: false, umip: false, pku: false,
            ospke: false, avx512vbmi2: false, cet_ss: false, gfni: false, vaes: false,
            vpclmulqdq: false, avx512vnni: false, avx512bitalg: false, avx512vpopcntdq: false,
            la57: false, rdpid: false, avx512_4vnniw: false, avx512_4fmaps: false, fsrm: false,
            avx512vp2intersect: false, md_clear: false, serialize: false, hybrid: false,
            tsx_force_abort: false, cet_ibt: false, spec_ctrl: false, stibp: false,
            flush_cmd: false, arch_cap: false, ssbd: false, lahf_lm: false, cmp_legacy: false,
            svm: false, extapic: false, cr8_legacy: false, abm: false, sse4a: false,
            misalignsse: false, prefetch3d: false, osvw: false, ibs: false, xop: false,
            skinit: false, wdt: false, lwp: false, fma4: false, tce: false, tbm: false,
            topology: false, perfctr_core: false, perfctr_nb: false, dbx: false, perftsc: false,
            pcx_l2i: false, syscall: false, mp: false, nx: false, mmxext: false, fxsr_opt: false,
            pdpe1gb: false, rdtscp: false, lm: false, _3dnowext: false, _3dnow: false,
        }
    }

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

pub fn has_feature(features: &CpuFeatures, name: &str) -> bool {
    match name {
        "sse" => features.sse,
        "sse2" => features.sse2,
        "sse3" => features.sse3,
        "ssse3" => features.ssse3,
        "sse4.1" | "sse4_1" => features.sse4_1,
        "sse4.2" | "sse4_2" => features.sse4_2,
        "avx" => features.avx,
        "avx2" => features.avx2,
        "avx512f" => features.avx512f,
        "aes" | "aes-ni" | "aesni" => features.aes_ni,
        "pclmulqdq" => features.pclmulqdq,
        "rdrand" => features.rdrand,
        "rdseed" => features.rdseed,
        "sha" => features.sha,
        "fma" => features.fma,
        "bmi1" => features.bmi1,
        "bmi2" => features.bmi2,
        "popcnt" => features.popcnt,
        "vmx" => features.vmx,
        "svm" => features.svm,
        "smep" => features.smep,
        "smap" => features.smap,
        "nx" => features.nx,
        "pcid" => features.pcid,
        "invpcid" => features.invpcid,
        "fsgsbase" => features.fsgsbase,
        "xsave" => features.xsave,
        "tsc" => features.tsc,
        "rdtscp" => features.rdtscp,
        "x2apic" => features.x2apic,
        "pku" => features.pku,
        "la57" => features.la57,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_features_default() {
        let features = CpuFeatures::new();
        assert!(!features.sse);
        assert!(!features.avx);
        assert!(!features.aes_ni);
    }
}
