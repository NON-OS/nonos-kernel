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

pub fn detect_extended_ecx(features: &mut CpuFeatures, ecx: u32) {
    features.lahf_lm = ecx & (1 << 0) != 0; features.cmp_legacy = ecx & (1 << 1) != 0;
    features.svm = ecx & (1 << 2) != 0; features.extapic = ecx & (1 << 3) != 0;
    features.cr8_legacy = ecx & (1 << 4) != 0; features.abm = ecx & (1 << 5) != 0;
    features.sse4a = ecx & (1 << 6) != 0; features.misalignsse = ecx & (1 << 7) != 0;
    features.prefetch3d = ecx & (1 << 8) != 0; features.osvw = ecx & (1 << 9) != 0;
    features.ibs = ecx & (1 << 10) != 0; features.xop = ecx & (1 << 11) != 0;
    features.skinit = ecx & (1 << 12) != 0; features.wdt = ecx & (1 << 13) != 0;
    features.lwp = ecx & (1 << 15) != 0; features.fma4 = ecx & (1 << 16) != 0;
    features.tce = ecx & (1 << 17) != 0; features.tbm = ecx & (1 << 21) != 0;
    features.topology = ecx & (1 << 22) != 0; features.perfctr_core = ecx & (1 << 23) != 0;
    features.perfctr_nb = ecx & (1 << 24) != 0; features.dbx = ecx & (1 << 26) != 0;
    features.perftsc = ecx & (1 << 27) != 0; features.pcx_l2i = ecx & (1 << 28) != 0;
}

pub fn detect_extended_edx(features: &mut CpuFeatures, edx: u32) {
    features.syscall = edx & (1 << 11) != 0; features.mp = edx & (1 << 19) != 0;
    features.nx = edx & (1 << 20) != 0; features.mmxext = edx & (1 << 22) != 0;
    features.fxsr_opt = edx & (1 << 25) != 0; features.pdpe1gb = edx & (1 << 26) != 0;
    features.rdtscp = edx & (1 << 27) != 0; features.lm = edx & (1 << 29) != 0;
    features._3dnowext = edx & (1 << 30) != 0; features._3dnow = edx & (1u32 << 31) != 0;
}
