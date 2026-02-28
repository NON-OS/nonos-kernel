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

pub mod fadt_flags {
    pub const WBINVD: u32 = 1 << 0;
    pub const WBINVD_FLUSH: u32 = 1 << 1;
    pub const PROC_C1: u32 = 1 << 2;
    pub const P_LVL2_UP: u32 = 1 << 3;
    pub const PWR_BUTTON: u32 = 1 << 4;
    pub const SLP_BUTTON: u32 = 1 << 5;
    pub const FIX_RTC: u32 = 1 << 6;
    pub const RTC_S4: u32 = 1 << 7;
    pub const TMR_VAL_EXT: u32 = 1 << 8;
    pub const DCK_CAP: u32 = 1 << 9;
    pub const RESET_REG_SUP: u32 = 1 << 10;
    pub const SEALED_CASE: u32 = 1 << 11;
    pub const HEADLESS: u32 = 1 << 12;
    pub const CPU_SW_SLP: u32 = 1 << 13;
    pub const PCI_EXP_WAK: u32 = 1 << 14;
    pub const USE_PLATFORM_CLOCK: u32 = 1 << 15;
    pub const S4_RTC_STS_VALID: u32 = 1 << 16;
    pub const REMOTE_POWER_ON: u32 = 1 << 17;
    pub const FORCE_APIC_CLUSTER: u32 = 1 << 18;
    pub const FORCE_APIC_PHYS: u32 = 1 << 19;
    pub const HW_REDUCED_ACPI: u32 = 1 << 20;
    pub const LOW_POWER_S0: u32 = 1 << 21;
}

pub mod boot_flags {
    pub const LEGACY_DEVICES: u16 = 1 << 0;
    pub const HAS_8042: u16 = 1 << 1;
    pub const NO_VGA: u16 = 1 << 2;
    pub const NO_MSI: u16 = 1 << 3;
    pub const NO_ASPM: u16 = 1 << 4;
    pub const NO_CMOS_RTC: u16 = 1 << 5;
}
