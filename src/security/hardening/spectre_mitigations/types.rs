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

#[derive(Debug, Clone, Copy)]
pub struct CpuVulnerabilities {
    pub spectre_v1: bool,
    pub spectre_v2: bool,
    pub spectre_v4: bool,
    pub meltdown: bool,
    pub mds: bool,
    pub l1tf: bool,
    pub taa: bool,
    pub srbds: bool,
    pub retbleed: bool,
    pub mmio_stale_data: bool,
}

impl Default for CpuVulnerabilities {
    fn default() -> Self {
        Self {
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
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MitigationStatus {
    pub kpti_enabled: bool,
    pub retpoline_enabled: bool,
    pub ibrs_enabled: bool,
    pub ibpb_enabled: bool,
    pub stibp_enabled: bool,
    pub ssbd_enabled: bool,
    pub mds_clear_enabled: bool,
    pub l1d_flush_enabled: bool,
    pub taa_mitigation_enabled: bool,
    pub rsb_stuffing_enabled: bool,
}

impl Default for MitigationStatus {
    fn default() -> Self {
        Self {
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
        }
    }
}
