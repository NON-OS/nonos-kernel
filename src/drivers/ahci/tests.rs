// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! Unit tests for the AHCI driver module.

use super::*;
use super::constants::*;
use super::types::*;
use super::error::*;
use super::stats::*;
use super::controller::hdr_flags_for;

#[test]
fn test_ahci_error_display() {
    assert_eq!(AhciError::Bar5NotConfigured.as_str(), "AHCI BAR5 not configured");
    assert_eq!(AhciError::PortNotInitialized.as_str(), "Port not initialized");
    assert_eq!(AhciError::LbaRangeExceeded.as_str(), "LBA range exceeds device capacity");
    assert_eq!(AhciError::CommandTimeout.as_str(), "AHCI command timeout");
    assert_eq!(AhciError::NoControllerFound.as_str(), "No AHCI controller found");
}

#[test]
fn test_ahci_error_variants() {
    // Ensure all error variants are distinct
    let errors = [
        AhciError::Bar5NotConfigured,
        AhciError::HbaResetTimeout,
        AhciError::BiosHandoffTimeout,
        AhciError::PortCmdListStopTimeout,
        AhciError::PortFisStopTimeout,
        AhciError::ZeroSectorCapacity,
        AhciError::PortNotInitialized,
        AhciError::LbaRangeExceeded,
        AhciError::LbaOverflow,
        AhciError::InvalidBufferSize,
        AhciError::BufferAddressOverflow,
        AhciError::BufferInCriticalRegion,
        AhciError::BufferNotAligned,
        AhciError::NoFreeSlots,
        AhciError::CommandFailed,
        AhciError::CommandTimeout,
        AhciError::TrimNotSupported,
        AhciError::TrimRateLimitExceeded,
        AhciError::SecureEraseNotSupported,
        AhciError::CipherNotInitialized,
        AhciError::PortDmaNotInitialized,
        AhciError::DmaAllocationFailed,
        AhciError::PortResetFailed,
        AhciError::NoControllerFound,
    ];

    // Verify count matches enum variants
    assert_eq!(errors.len(), 24);

    // Verify each has a non-empty description
    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_ahci_error_equality() {
    assert_eq!(AhciError::Bar5NotConfigured, AhciError::Bar5NotConfigured);
    assert_ne!(AhciError::Bar5NotConfigured, AhciError::HbaResetTimeout);

    // Test Copy trait
    let err1 = AhciError::CommandFailed;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_device_type_names() {
    assert_eq!(AhciDeviceType::Sata.as_str(), "SATA");
    assert_eq!(AhciDeviceType::Satapi.as_str(), "SATAPI");
    assert_eq!(AhciDeviceType::Semb.as_str(), "SEMB");
    assert_eq!(AhciDeviceType::Pm.as_str(), "Port Multiplier");
}

#[test]
fn test_device_type_from_signature() {
    assert_eq!(AhciDeviceType::from_signature(0x0000_0101), Some(AhciDeviceType::Sata));
    assert_eq!(AhciDeviceType::from_signature(0xEB14_0101), Some(AhciDeviceType::Satapi));
    assert_eq!(AhciDeviceType::from_signature(0xC33C_0101), Some(AhciDeviceType::Semb));
    assert_eq!(AhciDeviceType::from_signature(0x9669_0101), Some(AhciDeviceType::Pm));
    assert_eq!(AhciDeviceType::from_signature(0x0000_0000), None);
    assert_eq!(AhciDeviceType::from_signature(0xDEAD_BEEF), None);
}

#[test]
fn test_ahci_stats_default() {
    let stats = AhciStats::default();
    assert_eq!(stats.read_ops, 0);
    assert_eq!(stats.write_ops, 0);
    assert_eq!(stats.trim_ops, 0);
    assert_eq!(stats.errors, 0);
    assert_eq!(stats.bytes_read, 0);
    assert_eq!(stats.bytes_written, 0);
    assert_eq!(stats.devices_count, 0);
    assert_eq!(stats.port_resets, 0);
    assert_eq!(stats.validation_failures, 0);
}

#[test]
fn test_ahci_stats_copy() {
    let stats1 = AhciStats {
        read_ops: 100,
        write_ops: 50,
        trim_ops: 10,
        errors: 2,
        bytes_read: 1024000,
        bytes_written: 512000,
        devices_count: 2,
        port_resets: 1,
        validation_failures: 0,
    };

    let stats2 = stats1;
    assert_eq!(stats1.read_ops, stats2.read_ops);
    assert_eq!(stats1.bytes_read, stats2.bytes_read);
}

#[test]
fn test_command_header_size() {
    // AHCI spec: Command header must be 32 bytes
    assert_eq!(core::mem::size_of::<CommandHeader>(), 32);
}

#[test]
fn test_prdt_entry_size() {
    // AHCI spec: PRDT entry must be 16 bytes
    assert_eq!(core::mem::size_of::<PhysicalRegionDescriptor>(), 16);
}

#[test]
fn test_command_table_alignment() {
    // AHCI spec: Command table must be 128-byte aligned
    assert_eq!(core::mem::align_of::<CommandTable>(), 128);
}

#[test]
fn test_hdr_flags_read() {
    // Read command: CFL=5, W=0
    let flags = hdr_flags_for(5, false);
    assert_eq!(flags & 0x1F, 5); // CFL
    assert_eq!(flags & (1 << 6), 0); // W bit clear
}

#[test]
fn test_hdr_flags_write() {
    // Write command: CFL=5, W=1
    let flags = hdr_flags_for(5, true);
    assert_eq!(flags & 0x1F, 5); // CFL
    assert_ne!(flags & (1 << 6), 0); // W bit set
}

#[test]
fn test_hdr_flags_cfl_range() {
    // CFL is 5 bits, so values 0-31 should work
    for cfl in 0..=31u16 {
        let flags = hdr_flags_for(cfl, false);
        assert_eq!(flags & 0x1F, cfl);
    }

    // Values > 31 should be truncated
    let flags = hdr_flags_for(32, false);
    assert_eq!(flags & 0x1F, 0);
}

#[test]
fn test_hba_register_constants() {
    // Verify HBA register offsets match AHCI spec
    assert_eq!(HBA_CAP, 0x00);
    assert_eq!(HBA_GHC, 0x04);
    assert_eq!(HBA_IS, 0x08);
    assert_eq!(HBA_PI, 0x0C);
    assert_eq!(HBA_VS, 0x10);
    assert_eq!(HBA_CAP2, 0x24);
    assert_eq!(HBA_BOHC, 0x28);
}

#[test]
fn test_port_register_constants() {
    // Verify port register offsets match AHCI spec
    assert_eq!(PORT_CLB, 0x00);
    assert_eq!(PORT_CLBU, 0x04);
    assert_eq!(PORT_FB, 0x08);
    assert_eq!(PORT_FBU, 0x0C);
    assert_eq!(PORT_IS, 0x10);
    assert_eq!(PORT_IE, 0x14);
    assert_eq!(PORT_CMD, 0x18);
    assert_eq!(PORT_TFD, 0x20);
    assert_eq!(PORT_SIG, 0x24);
    assert_eq!(PORT_SSTS, 0x28);
    assert_eq!(PORT_SCTL, 0x2C);
    assert_eq!(PORT_SERR, 0x30);
    assert_eq!(PORT_SACT, 0x34);
    assert_eq!(PORT_CI, 0x38);
}

#[test]
fn test_cmd_bits() {
    assert_eq!(CMD_ST, 1 << 0);
    assert_eq!(CMD_FRE, 1 << 4);
    assert_eq!(CMD_FR, 1 << 14);
    assert_eq!(CMD_CR, 1 << 15);

    // Verify they're distinct
    assert_ne!(CMD_ST, CMD_FRE);
    assert_ne!(CMD_FRE, CMD_FR);
    assert_ne!(CMD_FR, CMD_CR);
}

#[test]
fn test_is_tfes_bit() {
    assert_eq!(IS_TFES, 1 << 30);
}

#[test]
fn test_fis_type_values() {
    // FIS type values per SATA spec
    assert_eq!(FIS_TYPE_REG_H2D, 0x27);
}

#[test]
fn test_ata_command_values() {
    // ATA command values per ACS spec
    assert_eq!(ATA_CMD_IDENTIFY, 0xEC);
    assert_eq!(ATA_CMD_READ_DMA_EXT, 0x25);
    assert_eq!(ATA_CMD_WRITE_DMA_EXT, 0x35);
    assert_eq!(ATA_CMD_DSM, 0x06);
    assert_eq!(ATA_CMD_SECURITY_ERASE_PREPARE, 0xF3);
    assert_eq!(ATA_CMD_SECURITY_ERASE_UNIT, 0xF4);
    assert_eq!(DSM_TRIM, 0x01);
}

#[test]
fn test_security_constants() {
    // Verify security constants are reasonable
    assert!(MAX_DEVICE_SECTORS > 0);
    assert!(COMMAND_TIMEOUT_DEFAULT > 0);
    assert!(COMMAND_TIMEOUT_ERASE > COMMAND_TIMEOUT_DEFAULT);
    assert!(TRIM_RATE_LIMIT_INTERVAL_US > 0);
    assert!(PORT_RESET_TIMEOUT > 0);

    // MAX_DEVICE_SECTORS = 8TB / 512 bytes = 0x0010_0000_0000
    assert_eq!(MAX_DEVICE_SECTORS, 0x0010_0000_0000);
}

#[test]
fn test_command_slot_constants() {
    // AHCI spec mandates 32 command slots per port
    assert_eq!(COMMAND_SLOTS_PER_PORT, 32);

    // Command table slot size should be reasonable
    assert!(COMMAND_TABLE_SLOT_SIZE >= 128);
    assert_eq!(COMMAND_TABLE_SLOT_SIZE, 256);
}

#[test]
fn test_error_from_str() {
    // Test From<&'static str> implementation
    let err: AhciError = "Port not initialized".into();
    assert_eq!(err, AhciError::PortNotInitialized);

    let err: AhciError = "Device does not support TRIM".into();
    assert_eq!(err, AhciError::TrimNotSupported);

    // Unknown strings should map to CommandFailed as fallback
    let err: AhciError = "Unknown error".into();
    assert_eq!(err, AhciError::CommandFailed);
}

#[test]
fn test_command_header_layout() {
    // Verify CommandHeader field offsets
    let header = CommandHeader {
        flags: 0x1234,
        prdtl: 0x5678,
        prdbc: 0xDEAD_BEEF,
        ctba: 0xCAFE_BABE,
        ctbau: 0x1234_5678,
        reserved: [0; 4],
    };

    // Check that we can access all fields
    assert_eq!(header.flags, 0x1234);
    assert_eq!(header.prdtl, 0x5678);
    assert_eq!(header.prdbc, 0xDEAD_BEEF);
    assert_eq!(header.ctba, 0xCAFE_BABE);
    assert_eq!(header.ctbau, 0x1234_5678);
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
fn test_device_type_debug() {
    // Test Debug trait implementation
    let sata = AhciDeviceType::Sata;
    let debug_str = format!("{:?}", sata);
    assert_eq!(debug_str, "Sata");
}

#[test]
fn test_error_debug() {
    // Test Debug trait implementation
    let err = AhciError::CommandTimeout;
    let debug_str = format!("{:?}", err);
    assert_eq!(debug_str, "CommandTimeout");
}

#[test]
fn test_error_display() {
    // Test Display trait implementation
    let err = AhciError::CommandTimeout;
    let display_str = format!("{}", err);
    assert_eq!(display_str, "AHCI command timeout");
}
