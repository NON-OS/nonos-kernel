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

use crate::drivers::ahci::types::*;
use crate::drivers::ahci::controller::hdr_flags_for;

#[test]
fn test_device_type_sata_str() {
    assert_eq!(AhciDeviceType::Sata.as_str(), "SATA");
}

#[test]
fn test_device_type_satapi_str() {
    assert_eq!(AhciDeviceType::Satapi.as_str(), "SATAPI");
}

#[test]
fn test_device_type_semb_str() {
    assert_eq!(AhciDeviceType::Semb.as_str(), "SEMB");
}

#[test]
fn test_device_type_pm_str() {
    assert_eq!(AhciDeviceType::Pm.as_str(), "Port Multiplier");
}

#[test]
fn test_device_type_from_signature_sata() {
    assert_eq!(AhciDeviceType::from_signature(0x0000_0101), Some(AhciDeviceType::Sata));
}

#[test]
fn test_device_type_from_signature_satapi() {
    assert_eq!(AhciDeviceType::from_signature(0xEB14_0101), Some(AhciDeviceType::Satapi));
}

#[test]
fn test_device_type_from_signature_semb() {
    assert_eq!(AhciDeviceType::from_signature(0xC33C_0101), Some(AhciDeviceType::Semb));
}

#[test]
fn test_device_type_from_signature_pm() {
    assert_eq!(AhciDeviceType::from_signature(0x9669_0101), Some(AhciDeviceType::Pm));
}

#[test]
fn test_device_type_from_signature_invalid_zero() {
    assert_eq!(AhciDeviceType::from_signature(0x0000_0000), None);
}

#[test]
fn test_device_type_from_signature_invalid_random() {
    assert_eq!(AhciDeviceType::from_signature(0xDEAD_BEEF), None);
}

#[test]
fn test_device_type_from_signature_invalid_partial() {
    assert_eq!(AhciDeviceType::from_signature(0x0000_0100), None);
}

#[test]
fn test_device_type_equality() {
    assert_eq!(AhciDeviceType::Sata, AhciDeviceType::Sata);
    assert_ne!(AhciDeviceType::Sata, AhciDeviceType::Satapi);
}

#[test]
fn test_device_type_copy() {
    let dt1 = AhciDeviceType::Sata;
    let dt2 = dt1;
    assert_eq!(dt1, dt2);
}

#[test]
fn test_device_type_clone() {
    let dt1 = AhciDeviceType::Satapi;
    let dt2 = dt1.clone();
    assert_eq!(dt1, dt2);
}

#[test]
fn test_device_type_debug() {
    let dt = AhciDeviceType::Sata;
    let debug_str = format!("{:?}", dt);
    assert_eq!(debug_str, "Sata");
}

#[test]
fn test_command_header_size() {
    assert_eq!(core::mem::size_of::<CommandHeader>(), 32);
}

#[test]
fn test_prdt_entry_size() {
    assert_eq!(core::mem::size_of::<PhysicalRegionDescriptor>(), 16);
}

#[test]
fn test_command_table_alignment() {
    assert_eq!(core::mem::align_of::<CommandTable>(), 128);
}

#[test]
fn test_command_header_layout() {
    let header = CommandHeader {
        flags: 0x1234,
        prdtl: 0x5678,
        prdbc: 0xDEAD_BEEF,
        ctba: 0xCAFE_BABE,
        ctbau: 0x1234_5678,
        reserved: [0; 4],
    };

    assert_eq!(header.flags, 0x1234);
    assert_eq!(header.prdtl, 0x5678);
    assert_eq!(header.prdbc, 0xDEAD_BEEF);
    assert_eq!(header.ctba, 0xCAFE_BABE);
    assert_eq!(header.ctbau, 0x1234_5678);
}

#[test]
fn test_command_header_reserved_zeroed() {
    let header = CommandHeader {
        flags: 0,
        prdtl: 0,
        prdbc: 0,
        ctba: 0,
        ctbau: 0,
        reserved: [0; 4],
    };

    for r in header.reserved {
        assert_eq!(r, 0);
    }
}

#[test]
fn test_prdt_layout() {
    let prdt = PhysicalRegionDescriptor {
        dba: 0x1234_5678,
        dbau: 0x9ABC_DEF0,
        reserved0: 0,
        dbc: 0xFFFF_FFFF,
    };

    assert_eq!(prdt.dba, 0x1234_5678);
    assert_eq!(prdt.dbau, 0x9ABC_DEF0);
    assert_eq!(prdt.reserved0, 0);
    assert_eq!(prdt.dbc, 0xFFFF_FFFF);
}

#[test]
fn test_hdr_flags_read_cfl_5() {
    let flags = hdr_flags_for(5, false);
    assert_eq!(flags & 0x1F, 5);
    assert_eq!(flags & (1 << 6), 0);
}

#[test]
fn test_hdr_flags_write_cfl_5() {
    let flags = hdr_flags_for(5, true);
    assert_eq!(flags & 0x1F, 5);
    assert_ne!(flags & (1 << 6), 0);
}

#[test]
fn test_hdr_flags_cfl_range() {
    for cfl in 0..=31u16 {
        let flags = hdr_flags_for(cfl, false);
        assert_eq!(flags & 0x1F, cfl);
    }
}

#[test]
fn test_hdr_flags_cfl_overflow() {
    let flags = hdr_flags_for(32, false);
    assert_eq!(flags & 0x1F, 0);
}

#[test]
fn test_hdr_flags_cfl_max() {
    let flags = hdr_flags_for(31, false);
    assert_eq!(flags & 0x1F, 31);
}

#[test]
fn test_hdr_flags_cfl_zero() {
    let flags = hdr_flags_for(0, false);
    assert_eq!(flags & 0x1F, 0);
}

#[test]
fn test_hdr_flags_write_bit_position() {
    let flags = hdr_flags_for(0, true);
    assert_eq!(flags & (1 << 6), 1 << 6);
}

#[test]
fn test_ahci_hba_size() {
    assert!(core::mem::size_of::<AhciHba>() >= 44);
}

#[test]
fn test_command_table_cfis_size() {
    let ct = CommandTable {
        cfis: [0; 64],
        acmd: [0; 16],
        reserved: [0; 48],
        prdt: [PhysicalRegionDescriptor {
            dba: 0,
            dbau: 0,
            reserved0: 0,
            dbc: 0,
        }; 1],
    };
    assert_eq!(ct.cfis.len(), 64);
}

#[test]
fn test_command_table_acmd_size() {
    let ct = CommandTable {
        cfis: [0; 64],
        acmd: [0; 16],
        reserved: [0; 48],
        prdt: [PhysicalRegionDescriptor {
            dba: 0,
            dbau: 0,
            reserved0: 0,
            dbc: 0,
        }; 1],
    };
    assert_eq!(ct.acmd.len(), 16);
}

#[test]
fn test_command_table_reserved_size() {
    let ct = CommandTable {
        cfis: [0; 64],
        acmd: [0; 16],
        reserved: [0; 48],
        prdt: [PhysicalRegionDescriptor {
            dba: 0,
            dbau: 0,
            reserved0: 0,
            dbc: 0,
        }; 1],
    };
    assert_eq!(ct.reserved.len(), 48);
}
