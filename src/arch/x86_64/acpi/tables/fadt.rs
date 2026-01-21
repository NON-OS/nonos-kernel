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

use super::sdt::{SdtHeader, GenericAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmProfile {
    Unspecified = 0,
    Desktop = 1,
    Mobile = 2,
    Workstation = 3,
    EnterpriseServer = 4,
    SohoServer = 5,
    AppliancePc = 6,
    PerformanceServer = 7,
    Tablet = 8,
}

impl PmProfile {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Desktop,
            2 => Self::Mobile,
            3 => Self::Workstation,
            4 => Self::EnterpriseServer,
            5 => Self::SohoServer,
            6 => Self::AppliancePc,
            7 => Self::PerformanceServer,
            8 => Self::Tablet,
            _ => Self::Unspecified,
        }
    }

    pub fn is_server(&self) -> bool {
        matches!(self, Self::EnterpriseServer | Self::SohoServer | Self::PerformanceServer)
    }

    pub fn is_mobile(&self) -> bool {
        matches!(self, Self::Mobile | Self::Tablet)
    }
}

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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub header: SdtHeader,
    pub firmware_ctrl: u32,
    pub dsdt: u32,
    pub reserved1: u8,
    pub preferred_pm_profile: u8,
    pub sci_interrupt: u16,
    pub smi_command_port: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub pstate_control: u8,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm2_control_block: u32,
    pub pm_timer_block: u32,
    pub gpe0_block: u32,
    pub gpe1_block: u32,
    pub pm1_event_length: u8,
    pub pm1_control_length: u8,
    pub pm2_control_length: u8,
    pub pm_timer_length: u8,
    pub gpe0_length: u8,
    pub gpe1_length: u8,
    pub gpe1_base: u8,
    pub cst_control: u8,
    pub c2_latency: u16,
    pub c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,
    pub boot_architecture_flags: u16,
    pub reserved2: u8,
    pub flags: u32,
    pub reset_reg: GenericAddress,
    pub reset_value: u8,
    pub arm_boot_arch: u16,
    pub fadt_minor_version: u8,
    pub x_firmware_ctrl: u64,
    pub x_dsdt: u64,
    pub x_pm1a_event_block: GenericAddress,
    pub x_pm1b_event_block: GenericAddress,
    pub x_pm1a_control_block: GenericAddress,
    pub x_pm1b_control_block: GenericAddress,
    pub x_pm2_control_block: GenericAddress,
    pub x_pm_timer_block: GenericAddress,
    pub x_gpe0_block: GenericAddress,
    pub x_gpe1_block: GenericAddress,
    pub sleep_control_reg: GenericAddress,
    pub sleep_status_reg: GenericAddress,
    pub hypervisor_vendor_id: u64,
}

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

    pub fn dsdt_address(&self) -> u64 {
        if self.header.length >= 148 && self.x_dsdt != 0 {
            self.x_dsdt
        } else {
            self.dsdt as u64
        }
    }

    pub fn firmware_control_address(&self) -> u64 {
        if self.header.length >= 140 && self.x_firmware_ctrl != 0 {
            self.x_firmware_ctrl
        } else {
            self.firmware_ctrl as u64
        }
    }

    pub fn pm_profile(&self) -> PmProfile {
        PmProfile::from_u8(self.preferred_pm_profile)
    }

    pub fn pm1a_event_address(&self) -> u64 {
        if self.header.length >= 172 && self.x_pm1a_event_block.is_valid() {
            self.x_pm1a_event_block.address
        } else {
            self.pm1a_event_block as u64
        }
    }

    pub fn pm1b_event_address(&self) -> u64 {
        if self.header.length >= 184 && self.x_pm1b_event_block.is_valid() {
            self.x_pm1b_event_block.address
        } else {
            self.pm1b_event_block as u64
        }
    }

    pub fn pm1a_control_address(&self) -> u64 {
        if self.header.length >= 196 && self.x_pm1a_control_block.is_valid() {
            self.x_pm1a_control_block.address
        } else {
            self.pm1a_control_block as u64
        }
    }

    pub fn pm1b_control_address(&self) -> u64 {
        if self.header.length >= 208 && self.x_pm1b_control_block.is_valid() {
            self.x_pm1b_control_block.address
        } else {
            self.pm1b_control_block as u64
        }
    }

    pub fn pm_timer_address(&self) -> u64 {
        if self.header.length >= 232 && self.x_pm_timer_block.is_valid() {
            self.x_pm_timer_block.address
        } else {
            self.pm_timer_block as u64
        }
    }

    pub fn gpe0_address(&self) -> u64 {
        if self.header.length >= 244 && self.x_gpe0_block.is_valid() {
            self.x_gpe0_block.address
        } else {
            self.gpe0_block as u64
        }
    }

    pub fn gpe1_address(&self) -> u64 {
        if self.header.length >= 256 && self.x_gpe1_block.is_valid() {
            self.x_gpe1_block.address
        } else {
            self.gpe1_block as u64
        }
    }

    pub fn has_8042(&self) -> bool {
        self.boot_architecture_flags & boot_flags::HAS_8042 != 0
    }

    pub fn has_legacy_devices(&self) -> bool {
        self.boot_architecture_flags & boot_flags::LEGACY_DEVICES != 0
    }

    pub fn has_vga(&self) -> bool {
        self.boot_architecture_flags & boot_flags::NO_VGA == 0
    }

    pub fn has_msi(&self) -> bool {
        self.boot_architecture_flags & boot_flags::NO_MSI == 0
    }

    pub fn has_cmos_rtc(&self) -> bool {
        self.boot_architecture_flags & boot_flags::NO_CMOS_RTC == 0
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

pub mod pm1_status {
    pub const TMR_STS: u16 = 1 << 0;
    pub const BM_STS: u16 = 1 << 4;
    pub const GBL_STS: u16 = 1 << 5;
    pub const PWRBTN_STS: u16 = 1 << 8;
    pub const SLPBTN_STS: u16 = 1 << 9;
    pub const RTC_STS: u16 = 1 << 10;
    pub const PCIEXP_WAKE_STS: u16 = 1 << 14;
    pub const WAK_STS: u16 = 1 << 15;
}

pub mod pm1_enable {
    pub const TMR_EN: u16 = 1 << 0;
    pub const GBL_EN: u16 = 1 << 5;
    pub const PWRBTN_EN: u16 = 1 << 8;
    pub const SLPBTN_EN: u16 = 1 << 9;
    pub const RTC_EN: u16 = 1 << 10;
    pub const PCIEXP_WAKE_DIS: u16 = 1 << 14;
}

pub mod pm1_control {
    pub const SCI_EN: u16 = 1 << 0;
    pub const BM_RLD: u16 = 1 << 1;
    pub const GBL_RLS: u16 = 1 << 2;
    pub const SLP_TYP_SHIFT: u16 = 10;
    pub const SLP_TYP_MASK: u16 = 0x07 << SLP_TYP_SHIFT;
    pub const SLP_EN: u16 = 1 << 13;
}
