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

use crate::security::hardware::cpu::detect_cpu_security_features;
use crate::security::hardware::memory::detect_memory_protection;
use crate::security::hardware::tpm_detect::detect_tpm_capabilities;

use super::score::calculate_security_score;
use super::types::HardwareCapabilities;

pub fn detect_hardware_capabilities() -> HardwareCapabilities {
    let cpu = detect_cpu_security_features();
    let memory = detect_memory_protection();
    let tpm = detect_tpm_capabilities();
    let security_score = calculate_security_score(&cpu, &memory, &tpm);
    HardwareCapabilities { cpu, memory, tpm, security_score }
}
