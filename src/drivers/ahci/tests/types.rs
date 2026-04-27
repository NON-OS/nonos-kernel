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

use crate::drivers::ahci::controller::hdr_flags_for;
use crate::drivers::ahci::types::*;
use crate::test::framework::TestResult;

pub(crate) fn test_device_type_sata_str() -> TestResult {
    if AhciDeviceType::Sata.as_str() != "SATA" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_satapi_str() -> TestResult {
    if AhciDeviceType::Satapi.as_str() != "SATAPI" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_semb_str() -> TestResult {
    if AhciDeviceType::Semb.as_str() != "SEMB" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_pm_str() -> TestResult {
    if AhciDeviceType::Pm.as_str() != "Port Multiplier" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_sata() -> TestResult {
    if AhciDeviceType::from_signature(0x0000_0101) != Some(AhciDeviceType::Sata) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_satapi() -> TestResult {
    if AhciDeviceType::from_signature(0xEB14_0101) != Some(AhciDeviceType::Satapi) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_semb() -> TestResult {
    if AhciDeviceType::from_signature(0xC33C_0101) != Some(AhciDeviceType::Semb) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_pm() -> TestResult {
    if AhciDeviceType::from_signature(0x9669_0101) != Some(AhciDeviceType::Pm) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_invalid_zero() -> TestResult {
    if AhciDeviceType::from_signature(0x0000_0000) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_invalid_random() -> TestResult {
    if AhciDeviceType::from_signature(0xDEAD_BEEF) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_from_signature_invalid_partial() -> TestResult {
    if AhciDeviceType::from_signature(0x0000_0100) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_equality() -> TestResult {
    if AhciDeviceType::Sata != AhciDeviceType::Sata {
        return TestResult::Fail;
    }
    if AhciDeviceType::Sata == AhciDeviceType::Satapi {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_copy() -> TestResult {
    let dt1 = AhciDeviceType::Sata;
    let dt2 = dt1;
    if dt1 != dt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_clone() -> TestResult {
    let dt1 = AhciDeviceType::Satapi;
    let dt2 = dt1.clone();
    if dt1 != dt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_type_debug() -> TestResult {
    let dt = AhciDeviceType::Sata;
    let debug_str = format!("{:?}", dt);
    if debug_str != "Sata" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_header_size() -> TestResult {
    if core::mem::size_of::<CommandHeader>() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_prdt_entry_size() -> TestResult {
    if core::mem::size_of::<PhysicalRegionDescriptor>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_table_alignment() -> TestResult {
    if core::mem::align_of::<CommandTable>() != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_header_layout() -> TestResult {
    let header = CommandHeader {
        flags: 0x1234,
        prdtl: 0x5678,
        prdbc: 0xDEAD_BEEF,
        ctba: 0xCAFE_BABE,
        ctbau: 0x1234_5678,
        reserved: [0; 4],
    };

    if header.flags != 0x1234 {
        return TestResult::Fail;
    }
    if header.prdtl != 0x5678 {
        return TestResult::Fail;
    }
    if header.prdbc != 0xDEAD_BEEF {
        return TestResult::Fail;
    }
    if header.ctba != 0xCAFE_BABE {
        return TestResult::Fail;
    }
    if header.ctbau != 0x1234_5678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_header_reserved_zeroed() -> TestResult {
    let header =
        CommandHeader { flags: 0, prdtl: 0, prdbc: 0, ctba: 0, ctbau: 0, reserved: [0; 4] };

    for r in header.reserved {
        if r != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_prdt_layout() -> TestResult {
    let prdt = PhysicalRegionDescriptor {
        dba: 0x1234_5678,
        dbau: 0x9ABC_DEF0,
        reserved0: 0,
        dbc: 0xFFFF_FFFF,
    };

    if prdt.dba != 0x1234_5678 {
        return TestResult::Fail;
    }
    if prdt.dbau != 0x9ABC_DEF0 {
        return TestResult::Fail;
    }
    if prdt.reserved0 != 0 {
        return TestResult::Fail;
    }
    if prdt.dbc != 0xFFFF_FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_read_cfl_5() -> TestResult {
    let flags = hdr_flags_for(5, false);
    if flags & 0x1F != 5 {
        return TestResult::Fail;
    }
    if flags & (1 << 6) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_write_cfl_5() -> TestResult {
    let flags = hdr_flags_for(5, true);
    if flags & 0x1F != 5 {
        return TestResult::Fail;
    }
    if flags & (1 << 6) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_cfl_range() -> TestResult {
    for cfl in 0..=31u16 {
        let flags = hdr_flags_for(cfl, false);
        if flags & 0x1F != cfl {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_cfl_overflow() -> TestResult {
    let flags = hdr_flags_for(32, false);
    if flags & 0x1F != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_cfl_max() -> TestResult {
    let flags = hdr_flags_for(31, false);
    if flags & 0x1F != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_cfl_zero() -> TestResult {
    let flags = hdr_flags_for(0, false);
    if flags & 0x1F != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hdr_flags_write_bit_position() -> TestResult {
    let flags = hdr_flags_for(0, true);
    if flags & (1 << 6) != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ahci_hba_size() -> TestResult {
    if !(core::mem::size_of::<AhciHba>() >= 44) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_table_cfis_size() -> TestResult {
    let ct = CommandTable {
        cfis: [0; 64],
        acmd: [0; 16],
        reserved: [0; 48],
        prdt: [PhysicalRegionDescriptor { dba: 0, dbau: 0, reserved0: 0, dbc: 0 }; 1],
    };
    if ct.cfis.len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_table_acmd_size() -> TestResult {
    let ct = CommandTable {
        cfis: [0; 64],
        acmd: [0; 16],
        reserved: [0; 48],
        prdt: [PhysicalRegionDescriptor { dba: 0, dbau: 0, reserved0: 0, dbc: 0 }; 1],
    };
    if ct.acmd.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_table_reserved_size() -> TestResult {
    let ct = CommandTable {
        cfis: [0; 64],
        acmd: [0; 16],
        reserved: [0; 48],
        prdt: [PhysicalRegionDescriptor { dba: 0, dbau: 0, reserved0: 0, dbc: 0 }; 1],
    };
    if ct.reserved.len() != 48 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
