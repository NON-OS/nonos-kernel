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

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub sse3: bool, pub pclmulqdq: bool, pub dtes64: bool, pub monitor: bool, pub ds_cpl: bool,
    pub vmx: bool, pub smx: bool, pub est: bool, pub tm2: bool, pub ssse3: bool, pub cnxt_id: bool,
    pub fma: bool, pub cx16: bool, pub xtpr: bool, pub pdcm: bool, pub pcid: bool, pub dca: bool,
    pub sse4_1: bool, pub sse4_2: bool, pub x2apic: bool, pub movbe: bool, pub popcnt: bool,
    pub tsc_deadline: bool, pub aes_ni: bool, pub xsave: bool, pub osxsave: bool, pub avx: bool,
    pub f16c: bool, pub rdrand: bool, pub hypervisor: bool,
    pub fpu: bool, pub vme: bool, pub de: bool, pub pse: bool, pub tsc: bool, pub msr: bool,
    pub pae: bool, pub mce: bool, pub cx8: bool, pub apic: bool, pub sep: bool, pub mtrr: bool,
    pub pge: bool, pub mca: bool, pub cmov: bool, pub pat: bool, pub pse36: bool, pub psn: bool,
    pub clflush: bool, pub ds: bool, pub acpi: bool, pub mmx: bool, pub fxsr: bool, pub sse: bool,
    pub sse2: bool, pub ss: bool, pub htt: bool, pub tm: bool, pub ia64: bool, pub pbe: bool,
    pub fsgsbase: bool, pub tsc_adjust: bool, pub sgx: bool, pub bmi1: bool, pub hle: bool,
    pub avx2: bool, pub smep: bool, pub bmi2: bool, pub erms: bool, pub invpcid: bool, pub rtm: bool,
    pub pqm: bool, pub mpx: bool, pub pqe: bool, pub avx512f: bool, pub avx512dq: bool, pub rdseed: bool,
    pub adx: bool, pub smap: bool, pub avx512ifma: bool, pub clflushopt: bool, pub clwb: bool,
    pub avx512pf: bool, pub avx512er: bool, pub avx512cd: bool, pub sha: bool, pub avx512bw: bool,
    pub avx512vl: bool, pub prefetchwt1: bool, pub avx512vbmi: bool, pub umip: bool, pub pku: bool,
    pub ospke: bool, pub avx512vbmi2: bool, pub cet_ss: bool, pub gfni: bool, pub vaes: bool,
    pub vpclmulqdq: bool, pub avx512vnni: bool, pub avx512bitalg: bool, pub avx512vpopcntdq: bool,
    pub la57: bool, pub rdpid: bool, pub avx512_4vnniw: bool, pub avx512_4fmaps: bool, pub fsrm: bool,
    pub avx512vp2intersect: bool, pub md_clear: bool, pub serialize: bool, pub hybrid: bool,
    pub tsx_force_abort: bool, pub cet_ibt: bool, pub spec_ctrl: bool, pub stibp: bool,
    pub flush_cmd: bool, pub arch_cap: bool, pub ssbd: bool, pub lahf_lm: bool, pub cmp_legacy: bool,
    pub svm: bool, pub extapic: bool, pub cr8_legacy: bool, pub abm: bool, pub sse4a: bool,
    pub misalignsse: bool, pub prefetch3d: bool, pub osvw: bool, pub ibs: bool, pub xop: bool,
    pub skinit: bool, pub wdt: bool, pub lwp: bool, pub fma4: bool, pub tce: bool, pub tbm: bool,
    pub topology: bool, pub perfctr_core: bool, pub perfctr_nb: bool, pub dbx: bool, pub perftsc: bool,
    pub pcx_l2i: bool, pub syscall: bool, pub mp: bool, pub nx: bool, pub mmxext: bool, pub fxsr_opt: bool,
    pub pdpe1gb: bool, pub rdtscp: bool, pub lm: bool, pub _3dnowext: bool, pub _3dnow: bool,
}
