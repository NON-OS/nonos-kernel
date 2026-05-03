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

use super::error::PsciError;
use super::{psci_call0, psci_call1};

const PSCI_VERSION: u32 = 0x8400_0000;
const PSCI_FEATURES: u32 = 0x8400_000A;

#[derive(Debug, Clone, Copy)]
pub struct PsciVersion {
    pub major: u16,
    pub minor: u16,
}

impl PsciVersion {
    pub fn from_raw(raw: u32) -> Self {
        Self { major: (raw >> 16) as u16, minor: (raw & 0xFFFF) as u16 }
    }

    pub fn is_v1(&self) -> bool {
        self.major >= 1
    }

    pub fn supports_features(&self) -> bool {
        self.major >= 1
    }
}

impl core::fmt::Display for PsciVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

pub fn psci_version() -> PsciVersion {
    let ret = psci_call0(PSCI_VERSION);
    PsciVersion::from_raw(ret as u32)
}

pub fn features(func_id: u32) -> Result<u32, PsciError> {
    let ret = psci_call1(PSCI_FEATURES, func_id as u64);

    if ret < 0 {
        PsciError::from_ret(ret as i32)?;
    }

    Ok(ret as u32)
}

pub fn is_function_supported(func_id: u32) -> bool {
    features(func_id).is_ok()
}

pub fn has_cpu_suspend() -> bool {
    is_function_supported(0xC400_0001)
}

pub fn has_cpu_off() -> bool {
    is_function_supported(0x8400_0002)
}

pub fn has_cpu_on() -> bool {
    is_function_supported(0xC400_0003)
}

pub fn has_affinity_info() -> bool {
    is_function_supported(0xC400_0004)
}

pub fn has_system_off() -> bool {
    is_function_supported(0x8400_0008)
}

pub fn has_system_reset() -> bool {
    is_function_supported(0x8400_0009)
}

pub fn has_system_reset2() -> bool {
    is_function_supported(0xC400_0012)
}

pub fn has_system_suspend() -> bool {
    is_function_supported(0xC400_000E)
}

pub fn has_mem_protect() -> bool {
    is_function_supported(0x8400_0013)
}

#[derive(Debug, Clone)]
pub struct PsciCapabilities {
    pub version: PsciVersion,
    pub cpu_suspend: bool,
    pub cpu_off: bool,
    pub cpu_on: bool,
    pub affinity_info: bool,
    pub system_off: bool,
    pub system_reset: bool,
    pub system_reset2: bool,
    pub system_suspend: bool,
    pub mem_protect: bool,
}

impl PsciCapabilities {
    pub fn discover() -> Self {
        let version = psci_version();

        Self {
            version,
            cpu_suspend: has_cpu_suspend(),
            cpu_off: has_cpu_off(),
            cpu_on: has_cpu_on(),
            affinity_info: has_affinity_info(),
            system_off: has_system_off(),
            system_reset: has_system_reset(),
            system_reset2: has_system_reset2(),
            system_suspend: has_system_suspend(),
            mem_protect: has_mem_protect(),
        }
    }
}
