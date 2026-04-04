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

use crate::drivers::ahci::constants::*;

#[test]
fn test_hba_register_offsets() {
    assert_eq!(HBA_CAP, 0x00);
    assert_eq!(HBA_GHC, 0x04);
    assert_eq!(HBA_IS, 0x08);
    assert_eq!(HBA_PI, 0x0C);
    assert_eq!(HBA_VS, 0x10);
    assert_eq!(HBA_CAP2, 0x24);
    assert_eq!(HBA_BOHC, 0x28);
}

#[test]
fn test_port_register_offsets() {
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
}

#[test]
fn test_cmd_bits_unique() {
    assert_ne!(CMD_ST, CMD_FRE);
    assert_ne!(CMD_FRE, CMD_FR);
    assert_ne!(CMD_FR, CMD_CR);
    assert_ne!(CMD_ST, CMD_CR);
}

#[test]
fn test_is_tfes_bit() {
    assert_eq!(IS_TFES, 1 << 30);
}

#[test]
fn test_fis_type_values() {
    assert_eq!(FIS_TYPE_REG_H2D, 0x27);
}

#[test]
fn test_ata_identify_command() {
    assert_eq!(ATA_CMD_IDENTIFY, 0xEC);
}

#[test]
fn test_ata_read_write_commands() {
    assert_eq!(ATA_CMD_READ_DMA_EXT, 0x25);
    assert_eq!(ATA_CMD_WRITE_DMA_EXT, 0x35);
}

#[test]
fn test_ata_dsm_command() {
    assert_eq!(ATA_CMD_DSM, 0x06);
    assert_eq!(DSM_TRIM, 0x01);
}

#[test]
fn test_ata_security_commands() {
    assert_eq!(ATA_CMD_SECURITY_ERASE_PREPARE, 0xF3);
    assert_eq!(ATA_CMD_SECURITY_ERASE_UNIT, 0xF4);
}

#[test]
fn test_max_device_sectors() {
    assert_eq!(MAX_DEVICE_SECTORS, 0x0010_0000_0000);
    assert!(MAX_DEVICE_SECTORS > 0);
}

#[test]
fn test_command_timeouts() {
    assert!(COMMAND_TIMEOUT_DEFAULT > 0);
    assert!(COMMAND_TIMEOUT_ERASE > COMMAND_TIMEOUT_DEFAULT);
    assert_eq!(COMMAND_TIMEOUT_DEFAULT, 5_000_000);
    assert_eq!(COMMAND_TIMEOUT_ERASE, 3600_000_000);
}

#[test]
fn test_trim_rate_limit() {
    assert!(TRIM_RATE_LIMIT_INTERVAL_US > 0);
    assert_eq!(TRIM_RATE_LIMIT_INTERVAL_US, 10_000);
}

#[test]
fn test_port_reset_timeout() {
    assert!(PORT_RESET_TIMEOUT > 0);
    assert_eq!(PORT_RESET_TIMEOUT, 1_000_000);
}

#[test]
fn test_command_slot_constants() {
    assert_eq!(COMMAND_SLOTS_PER_PORT, 32);
    assert_eq!(COMMAND_TABLE_SLOT_SIZE, 256);
    assert!(COMMAND_TABLE_SLOT_SIZE >= 128);
}

#[test]
fn test_port_register_spacing() {
    assert_eq!(PORT_IE - PORT_IS, 0x04);
    assert_eq!(PORT_CMD - PORT_IE, 0x04);
    assert_eq!(PORT_TFD - PORT_CMD, 0x08);
}

#[test]
fn test_hba_register_spacing() {
    assert_eq!(HBA_GHC - HBA_CAP, 0x04);
    assert_eq!(HBA_IS - HBA_GHC, 0x04);
    assert_eq!(HBA_PI - HBA_IS, 0x04);
    assert_eq!(HBA_VS - HBA_PI, 0x04);
}
