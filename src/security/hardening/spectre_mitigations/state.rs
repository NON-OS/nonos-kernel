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

use core::sync::atomic::AtomicBool;
use super::types::{CpuVulnerabilities, MitigationStatus};

pub(super) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(super) static MITIGATIONS_ENABLED: AtomicBool = AtomicBool::new(false);

pub(super) static mut CPU_VULNERABILITIES: CpuVulnerabilities = CpuVulnerabilities {
    spectre_v1: true,
    spectre_v2: true,
    spectre_v4: true,
    meltdown: true,
    mds: true,
    l1tf: true,
    taa: true,
    srbds: true,
    retbleed: true,
    mmio_stale_data: true,
};

pub(super) static mut MITIGATION_STATUS: MitigationStatus = MitigationStatus {
    kpti_enabled: false,
    retpoline_enabled: true,
    ibrs_enabled: false,
    ibpb_enabled: false,
    stibp_enabled: false,
    ssbd_enabled: false,
    mds_clear_enabled: false,
    l1d_flush_enabled: false,
    taa_mitigation_enabled: false,
    rsb_stuffing_enabled: false,
};
