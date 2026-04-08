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
fn test_smramc_bits() {
    assert_eq!(smramc_bits::G_SMRAME, 0x08);
    assert_eq!(smramc_bits::D_LCK, 0x10);
    assert_eq!(smramc_bits::D_CLS, 0x20);
    assert_eq!(smramc_bits::D_OPEN, 0x40);
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
