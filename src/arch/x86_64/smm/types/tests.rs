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
