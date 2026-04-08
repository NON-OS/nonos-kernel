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

use super::types_struct::CpuFeatures;

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
}
