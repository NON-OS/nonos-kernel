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

pub const SMRAMC_REGISTER: u16 = 0x88;

pub mod smramc {
    pub const G_SMRAME: u8 = 0x08;
    pub const D_LCK: u8 = 0x10;
    pub const D_CLS: u8 = 0x20;
    pub const D_OPEN: u8 = 0x40;
}

pub mod amd_msr {
    pub const SMM_BASE: u32 = 0xC001_0111;
    pub const SMM_ADDR: u32 = 0xC001_0112;
    pub const SMM_MASK: u32 = 0xC001_0113;
    pub const LOCK_BIT: u64 = 0x2;
}

pub mod intel_msr {
    pub const IA32_FEATURE_CONTROL: u32 = 0x3A;
    pub const SMM_FEATURE_CONTROL: u32 = 0x4E0;
    pub const SMM_CODE_CHK_EN: u64 = 0x1;
    pub const SMM_BWP: u64 = 0x2;
}

pub const SMI_EN_OFFSET: u16 = 0x30;
pub const SMI_STS_OFFSET: u16 = 0x34;

pub mod smi_en {
    pub const GBL_SMI_EN: u32 = 1 << 0;
    pub const EOS: u32 = 1 << 1;
    pub const BIOS_EN: u32 = 1 << 2;
    pub const LEGACY_USB_EN: u32 = 1 << 3;
    pub const SLP_SMI_EN: u32 = 1 << 4;
    pub const APMC_EN: u32 = 1 << 5;
    pub const SWSMI_TMR_EN: u32 = 1 << 6;
    pub const BIOS_RLS: u32 = 1 << 7;
    pub const TCO_EN: u32 = 1 << 13;
    pub const PERIODIC_EN: u32 = 1 << 14;
    pub const SERIRQ_SMI_EN: u32 = 1 << 15;
    pub const SMBUS_SMI_EN: u32 = 1 << 16;
    pub const GPIO_EN: u32 = 1 << 18;
    pub const USB_EN: u32 = 1 << 19;
}

pub mod cr4 {
    pub const SMEP: u64 = 1 << 20;
    pub const SMAP: u64 = 1 << 21;
}

pub const LEGACY_SMRAM_BASE: u64 = 0xA0000;
pub const LEGACY_SMRAM_SIZE: u64 = 0x20000;
pub const SMM_ENTRY_OFFSET: u64 = 0x8000;
pub const SMM_SAVE_STATE_32: u64 = 0xFE00;
pub const SMM_SAVE_STATE_64: u64 = 0xFC00;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smramc_bits() {
        assert_eq!(smramc::G_SMRAME, 0x08);
        assert_eq!(smramc::D_LCK, 0x10);
        assert_eq!(smramc::D_CLS, 0x20);
        assert_eq!(smramc::D_OPEN, 0x40);
    }

    #[test]
    fn test_amd_msr_constants() {
        assert_eq!(amd_msr::SMM_BASE, 0xC001_0111);
        assert_eq!(amd_msr::SMM_ADDR, 0xC001_0112);
        assert_eq!(amd_msr::SMM_MASK, 0xC001_0113);
        assert_eq!(amd_msr::LOCK_BIT, 0x2);
    }

    #[test]
    fn test_intel_msr_constants() {
        assert_eq!(intel_msr::IA32_FEATURE_CONTROL, 0x3A);
        assert_eq!(intel_msr::SMM_FEATURE_CONTROL, 0x4E0);
        assert_eq!(intel_msr::SMM_CODE_CHK_EN, 0x1);
        assert_eq!(intel_msr::SMM_BWP, 0x2);
    }

    #[test]
    fn test_smi_en_bits() {
        assert_eq!(smi_en::GBL_SMI_EN, 1 << 0);
        assert_eq!(smi_en::LEGACY_USB_EN, 1 << 3);
        assert_eq!(smi_en::APMC_EN, 1 << 5);
        assert_eq!(smi_en::TCO_EN, 1 << 13);
    }
}
