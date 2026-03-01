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

use core::sync::atomic::Ordering;
use super::types::{CpuVulnerabilities, MitigationStatus};
use super::state::{INITIALIZED, MITIGATIONS_ENABLED, CPU_VULNERABILITIES, MITIGATION_STATUS};
use super::detect::{detect_vulnerabilities, enable_mitigations};

pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    crate::log::info!("[SECURITY] Initializing side-channel mitigations...");

    let vulns = detect_vulnerabilities();
    // SAFETY: Single initialization path, no concurrent access.
    unsafe { CPU_VULNERABILITIES = vulns; }

    crate::log::info!("[SECURITY] CPU Vulnerabilities detected:");
    crate::log::info!("  Spectre v1: {}", vulns.spectre_v1);
    crate::log::info!("  Spectre v2: {}", vulns.spectre_v2);
    crate::log::info!("  Spectre v4: {}", vulns.spectre_v4);
    crate::log::info!("  Meltdown: {}", vulns.meltdown);
    crate::log::info!("  MDS: {}", vulns.mds);
    crate::log::info!("  L1TF: {}", vulns.l1tf);

    let status = enable_mitigations();
    // SAFETY: Single initialization path, no concurrent access.
    unsafe { MITIGATION_STATUS = status; }

    crate::log::info!("[SECURITY] Mitigations enabled:");
    crate::log::info!("  KPTI: {}", status.kpti_enabled);
    crate::log::info!("  Retpoline: {}", status.retpoline_enabled);
    crate::log::info!("  IBRS: {}", status.ibrs_enabled);
    crate::log::info!("  IBPB: {}", status.ibpb_enabled);
    crate::log::info!("  STIBP: {}", status.stibp_enabled);
    crate::log::info!("  SSBD: {}", status.ssbd_enabled);
    crate::log::info!("  MDS Clear: {}", status.mds_clear_enabled);
    crate::log::info!("  L1D Flush: {}", status.l1d_flush_enabled);
    crate::log::info!("  RSB Stuffing: {}", status.rsb_stuffing_enabled);

    MITIGATIONS_ENABLED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn get_vulnerabilities() -> CpuVulnerabilities {
    // SAFETY: Read-only access after initialization.
    unsafe { CPU_VULNERABILITIES }
}

pub fn get_mitigation_status() -> MitigationStatus {
    // SAFETY: Read-only access after initialization.
    unsafe { MITIGATION_STATUS }
}

pub fn are_mitigations_enabled() -> bool {
    MITIGATIONS_ENABLED.load(Ordering::SeqCst)
}
