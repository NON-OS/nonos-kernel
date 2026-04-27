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

use super::fadt_struct::Fadt;
use super::flags::fadt_flags;
use super::profile::PmProfile;

impl Fadt {
    pub const MIN_LENGTH: u32 = 116;
    pub const ACPI_2_LENGTH: u32 = 244;

    pub fn has_reset_register(&self) -> bool {
        self.flags & fadt_flags::RESET_REG_SUP != 0 && self.reset_reg.is_valid()
    }
    pub fn is_hw_reduced(&self) -> bool {
        self.flags & fadt_flags::HW_REDUCED_ACPI != 0
    }
    pub fn is_pm_timer_32bit(&self) -> bool {
        self.flags & fadt_flags::TMR_VAL_EXT != 0
    }
    pub fn supports_low_power_s0(&self) -> bool {
        self.flags & fadt_flags::LOW_POWER_S0 != 0
    }
    pub fn pm_profile(&self) -> PmProfile {
        PmProfile::from_u8(self.preferred_pm_profile)
    }
    pub fn sci_interrupt(&self) -> u16 {
        self.sci_interrupt
    }
    pub fn c2_latency_us(&self) -> u16 {
        self.c2_latency
    }
    pub fn c3_latency_us(&self) -> u16 {
        self.c3_latency
    }
    pub fn supports_c2(&self) -> bool {
        self.c2_latency <= 100
    }
    pub fn supports_c3(&self) -> bool {
        self.c3_latency <= 1000
    }
}
