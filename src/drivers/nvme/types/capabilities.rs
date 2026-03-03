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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerCapabilities {
    pub max_queue_entries: u16,
    pub contiguous_queues_required: bool,
    pub arbitration_mechanisms: u8,
    pub timeout_500ms_units: u8,
    pub doorbell_stride: u8,
    pub subsystem_reset_supported: bool,
    pub command_sets_supported: u8,
    pub boot_partition_supported: bool,
    pub memory_page_size_min_shift: u8,
    pub memory_page_size_max_shift: u8,
    pub persistent_memory_region: bool,
    pub controller_memory_buffer: bool,
}

impl ControllerCapabilities {
    pub fn from_register(cap: u64) -> Self {
        Self {
            max_queue_entries: ((cap & super::super::constants::CAP_MQES_MASK) as u16) + 1,
            contiguous_queues_required: (cap & super::super::constants::CAP_CQR_BIT) != 0,
            arbitration_mechanisms: ((cap >> super::super::constants::CAP_AMS_SHIFT) & 0x3) as u8,
            timeout_500ms_units: ((cap >> super::super::constants::CAP_TO_SHIFT) & 0xFF) as u8,
            doorbell_stride: ((cap >> super::super::constants::CAP_DSTRD_SHIFT) & 0xF) as u8,
            subsystem_reset_supported: (cap & super::super::constants::CAP_NSSRS_BIT) != 0,
            command_sets_supported: ((cap >> super::super::constants::CAP_CSS_SHIFT) & 0xFF) as u8,
            boot_partition_supported: (cap & super::super::constants::CAP_BPS_BIT) != 0,
            memory_page_size_min_shift: ((cap >> super::super::constants::CAP_MPSMIN_SHIFT) & 0xF) as u8 + 12,
            memory_page_size_max_shift: ((cap >> super::super::constants::CAP_MPSMAX_SHIFT) & 0xF) as u8 + 12,
            persistent_memory_region: (cap & super::super::constants::CAP_PMRS_BIT) != 0,
            controller_memory_buffer: (cap & super::super::constants::CAP_CMBS_BIT) != 0,
        }
    }

    pub const fn min_page_size(&self) -> usize {
        1 << self.memory_page_size_min_shift
    }

    pub const fn max_page_size(&self) -> usize {
        1 << self.memory_page_size_max_shift
    }

    pub const fn timeout_ms(&self) -> u32 {
        (self.timeout_500ms_units as u32) * 500
    }

    pub fn supports_nvm_command_set(&self) -> bool {
        (self.command_sets_supported & 0x01) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerVersion {
    pub major: u16,
    pub minor: u8,
    pub tertiary: u8,
}

impl ControllerVersion {
    pub fn from_register(vs: u32) -> Self {
        Self {
            major: super::super::constants::version_major(vs),
            minor: super::super::constants::version_minor(vs),
            tertiary: super::super::constants::version_tertiary(vs),
        }
    }

    pub const fn is_at_least(&self, major: u16, minor: u8) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }
}

impl core::fmt::Display for ControllerVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.tertiary != 0 {
            write!(f, "{}.{}.{}", self.major, self.minor, self.tertiary)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}
