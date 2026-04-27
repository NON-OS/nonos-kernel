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

use super::capabilities::HardwareCapabilities;

pub fn verify_platform_security(caps: &HardwareCapabilities) -> PlatformVerification {
    PlatformVerification {
        exploit_mitigations: caps.cpu.smep && caps.cpu.smap && caps.cpu.nx_bit,
        spectre_mitigations: caps.cpu.ibrs && caps.cpu.stibp,
        memory_encryption: caps.memory.sme_available || caps.memory.tme_available,
        tpm_attestation: caps.tpm.present && caps.tpm.version_2_0,
        hardware_rng: caps.cpu.rdrand || caps.cpu.rdseed,
        aes_acceleration: caps.cpu.aes_ni,
        overall_secure: caps.security_score >= 70,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PlatformVerification {
    pub exploit_mitigations: bool,
    pub spectre_mitigations: bool,
    pub memory_encryption: bool,
    pub tpm_attestation: bool,
    pub hardware_rng: bool,
    pub aes_acceleration: bool,
    pub overall_secure: bool,
}

impl PlatformVerification {
    pub fn is_production_ready(&self) -> bool {
        self.exploit_mitigations && self.hardware_rng && self.overall_secure
    }
}
