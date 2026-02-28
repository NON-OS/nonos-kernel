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

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    Amd,
    Unknown,
}

impl CpuVendor {
    pub fn detect() -> Self {
        let result = core::arch::x86_64::__cpuid(0);
        let vendor_bytes: [u8; 12] = unsafe {
            core::mem::transmute([result.ebx, result.edx, result.ecx])
        };

        match &vendor_bytes {
            b"GenuineIntel" => Self::Intel,
            b"AuthenticAMD" => Self::Amd,
            _ => Self::Unknown,
        }
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Intel => "Intel",
            Self::Amd => "AMD",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmmRegionType {
    Aseg,
    Hseg,
    Tseg,
    Unknown,
}

impl SmmRegionType {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Aseg => "ASEG",
            Self::Hseg => "HSEG",
            Self::Tseg => "TSEG",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SmmRegion {
    pub base: u64,
    pub size: u64,
    pub region_type: SmmRegionType,
    pub protected: bool,
    pub open: bool,
}

impl SmmRegion {
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size)
    }

    pub const fn contains_range(&self, start: u64, size: u64) -> bool {
        start >= self.base && start.saturating_add(size) <= self.base.saturating_add(self.size)
    }
}

#[derive(Debug, Clone)]
pub struct SmmHandler {
    pub entry_point: u64,
    pub size: u32,
    pub hash: [u8; 32],
    pub verified: bool,
    pub region_type: SmmRegionType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmiSource {
    Software,
    Timer,
    IoTrap,
    Thermal,
    PowerButton,
    Tco,
    UsbLegacy,
    Gpio,
    Smbus,
    GlobalEnable,
    Unknown,
}

impl SmiSource {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Software => "Software",
            Self::Timer => "Timer",
            Self::IoTrap => "I/O Trap",
            Self::Thermal => "Thermal",
            Self::PowerButton => "Power Button",
            Self::Tco => "TCO Timer",
            Self::UsbLegacy => "USB Legacy",
            Self::Gpio => "GPIO",
            Self::Smbus => "SMBus",
            Self::GlobalEnable => "Global Enable",
            Self::Unknown => "Unknown",
        }
    }

    pub fn from_smi_sts(sts: u32) -> Self {
        if sts & (1 << 0) != 0 {
            Self::Software
        } else if sts & (1 << 4) != 0 {
            Self::Timer
        } else if sts & (1 << 5) != 0 {
            Self::IoTrap
        } else if sts & (1 << 6) != 0 {
            Self::Thermal
        } else if sts & (1 << 16) != 0 {
            Self::PowerButton
        } else if sts & (1 << 13) != 0 {
            Self::Tco
        } else if sts & (1 << 3) != 0 {
            Self::UsbLegacy
        } else if sts & (1 << 18) != 0 {
            Self::Gpio
        } else if sts & (1 << 16) != 0 {
            Self::Smbus
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmiInfo {
    pub smi_count: u64,
    pub last_source: SmiSource,
    pub smi_en: u32,
    pub smi_sts: u32,
    pub active_handlers: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_vendor_names() {
        assert_eq!(CpuVendor::Intel.name(), "Intel");
        assert_eq!(CpuVendor::Amd.name(), "AMD");
        assert_eq!(CpuVendor::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_region_type_names() {
        assert_eq!(SmmRegionType::Aseg.name(), "ASEG");
        assert_eq!(SmmRegionType::Hseg.name(), "HSEG");
        assert_eq!(SmmRegionType::Tseg.name(), "TSEG");
        assert_eq!(SmmRegionType::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_smi_source_names() {
        assert_eq!(SmiSource::Software.name(), "Software");
        assert_eq!(SmiSource::Timer.name(), "Timer");
        assert_eq!(SmiSource::IoTrap.name(), "I/O Trap");
        assert_eq!(SmiSource::Thermal.name(), "Thermal");
        assert_eq!(SmiSource::PowerButton.name(), "Power Button");
        assert_eq!(SmiSource::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_smi_source_decode() {
        assert_eq!(SmiSource::from_smi_sts(0x01), SmiSource::Software);
        assert_eq!(SmiSource::from_smi_sts(0x10), SmiSource::Timer);
        assert_eq!(SmiSource::from_smi_sts(0x20), SmiSource::IoTrap);
        assert_eq!(SmiSource::from_smi_sts(0x00), SmiSource::Unknown);
    }

    #[test]
    fn test_smm_region_contains() {
        let region = SmmRegion {
            base: 0xA0000,
            size: 0x20000,
            region_type: SmmRegionType::Aseg,
            protected: true,
            open: false,
        };

        assert!(region.contains(0xA0000));
        assert!(region.contains(0xBFFFF));
        assert!(!region.contains(0x9FFFF));
        assert!(!region.contains(0xC0000));
    }

    #[test]
    fn test_smm_region_contains_range() {
        let region = SmmRegion {
            base: 0xA0000,
            size: 0x20000,
            region_type: SmmRegionType::Aseg,
            protected: true,
            open: false,
        };

        assert!(region.contains_range(0xA0000, 0x1000));
        assert!(region.contains_range(0xA8000, 0x8000));
        assert!(!region.contains_range(0xBF000, 0x2000));
        assert!(!region.contains_range(0x9F000, 0x2000));
    }
}
