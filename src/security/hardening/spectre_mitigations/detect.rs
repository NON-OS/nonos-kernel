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

use super::types::{CpuVulnerabilities, MitigationStatus};
use super::cpuid;
use super::msr::rdmsr;
use super::constants::{MSR_IA32_ARCH_CAPABILITIES, ARCH_CAP_RDCL_NO, ARCH_CAP_SSB_NO, ARCH_CAP_MDS_NO, ARCH_CAP_TAA_NO, ARCH_CAP_SBDR_SSDP_NO};
use super::ibrs::ibrs_enable;
use super::stibp::stibp_enable;
use super::ssbd::ssbd_enable;

pub fn detect_vulnerabilities() -> CpuVulnerabilities {
    let mut vulns = CpuVulnerabilities::default();

    if cpuid::has_arch_capabilities() {
        // SAFETY: ARCH_CAPABILITIES MSR read is valid when feature is supported.
        let caps = unsafe { rdmsr(MSR_IA32_ARCH_CAPABILITIES) };

        if caps & ARCH_CAP_RDCL_NO != 0 {
            vulns.meltdown = false;
        }
        if caps & ARCH_CAP_SSB_NO != 0 {
            vulns.spectre_v4 = false;
        }
        if caps & ARCH_CAP_MDS_NO != 0 {
            vulns.mds = false;
        }
        if caps & ARCH_CAP_TAA_NO != 0 {
            vulns.taa = false;
        }
        if caps & ARCH_CAP_SBDR_SSDP_NO != 0 {
            vulns.srbds = false;
        }
    }

    if cpuid::is_amd() {
        vulns.meltdown = false;
        vulns.mds = false;
    }

    vulns
}

pub fn enable_mitigations() -> MitigationStatus {
    let mut status = MitigationStatus::default();

    if cpuid::has_ibrs_ibpb() {
        ibrs_enable();
        status.ibrs_enabled = true;
        status.ibpb_enabled = true;
    }

    if cpuid::has_stibp() {
        stibp_enable();
        status.stibp_enabled = true;
    }

    if cpuid::has_ssbd() {
        ssbd_enable();
        status.ssbd_enabled = true;
    }

    if cpuid::has_md_clear() {
        status.mds_clear_enabled = true;
    }

    if cpuid::has_l1d_flush() {
        status.l1d_flush_enabled = true;
    }

    status.rsb_stuffing_enabled = true;

    status.kpti_enabled = crate::memory::virt::is_kpti_enabled();

    status
}
