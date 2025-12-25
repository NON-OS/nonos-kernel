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
//! AHCI register offsets and constants per AHCI 1.3.1 specification.

// ============================================================================
// HBA Register Offsets (AHCI 1.3.1 Spec Section 3.1)
// ============================================================================

/// Host Capabilities register offset
pub const HBA_CAP: u32 = 0x00;
/// Global Host Control register offset
pub const HBA_GHC: u32 = 0x04;
/// Interrupt Status register offset
pub const HBA_IS: u32 = 0x08;
/// Ports Implemented register offset
pub const HBA_PI: u32 = 0x0C;
/// AHCI Version register offset
pub const HBA_VS: u32 = 0x10;
/// Extended Host Capabilities register offset
pub const HBA_CAP2: u32 = 0x24;
/// BIOS/OS Handoff Control and Status register offset
pub const HBA_BOHC: u32 = 0x28;

// ============================================================================
// Per-Port Register Offsets (AHCI 1.3.1 Spec Section 3.3)
// ============================================================================

/// Port Command List Base Address (lower 32 bits)
pub const PORT_CLB: u32 = 0x00;
/// Port Command List Base Address (upper 32 bits)
pub const PORT_CLBU: u32 = 0x04;
/// Port FIS Base Address (lower 32 bits)
pub const PORT_FB: u32 = 0x08;
/// Port FIS Base Address (upper 32 bits)
pub const PORT_FBU: u32 = 0x0C;
/// Port Interrupt Status
pub const PORT_IS: u32 = 0x10;
/// Port Interrupt Enable
pub const PORT_IE: u32 = 0x14;
/// Port Command and Status
pub const PORT_CMD: u32 = 0x18;
/// Port Task File Data
pub const PORT_TFD: u32 = 0x20;
/// Port Signature
pub const PORT_SIG: u32 = 0x24;
/// Port SATA Status (SCR0: SStatus)
pub const PORT_SSTS: u32 = 0x28;
/// Port SATA Control (SCR2: SControl)
pub const PORT_SCTL: u32 = 0x2C;
/// Port SATA Error (SCR1: SError)
pub const PORT_SERR: u32 = 0x30;
/// Port SATA Active (SCR3: SActive)
pub const PORT_SACT: u32 = 0x34;
/// Port Command Issue
pub const PORT_CI: u32 = 0x38;

// ============================================================================
// PxCMD Register Bits (AHCI 1.3.1 Spec Section 3.3.7)
// ============================================================================

/// Start: When set, the HBA may process the command list
pub const CMD_ST: u32 = 1 << 0;
/// FIS Receive Enable: When set, the HBA may post received FISes
pub const CMD_FRE: u32 = 1 << 4;
/// FIS Receive Running: Set when FIS receive DMA engine is running
pub const CMD_FR: u32 = 1 << 14;
/// Command List Running: Set when command list DMA engine is running
pub const CMD_CR: u32 = 1 << 15;

// ============================================================================
// PxIS Register Bits (AHCI 1.3.1 Spec Section 3.3.5)
// ============================================================================

/// Task File Error Status: Set when device reports an error
pub const IS_TFES: u32 = 1 << 30;

// ============================================================================
// FIS Types (Serial ATA Revision 3.0 Spec)
// ============================================================================

/// Register FIS - Host to Device
pub const FIS_TYPE_REG_H2D: u8 = 0x27;

// ============================================================================
// ATA Commands (ATA/ATAPI-8 ACS)
// ============================================================================

/// IDENTIFY DEVICE command
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
/// READ DMA EXT (48-bit LBA) command
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// WRITE DMA EXT (48-bit LBA) command
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
/// DATA SET MANAGEMENT command
pub const ATA_CMD_DSM: u8 = 0x06;
/// SECURITY ERASE PREPARE command
pub const ATA_CMD_SECURITY_ERASE_PREPARE: u8 = 0xF3;
/// SECURITY ERASE UNIT command
pub const ATA_CMD_SECURITY_ERASE_UNIT: u8 = 0xF4;

/// DSM TRIM subcommand (Feature register value)
pub const DSM_TRIM: u8 = 0x01;

// ============================================================================
// Security and Timing Constants
// ============================================================================

/// Maximum reasonable device size in sectors (8TB at 512 bytes/sector).
/// Devices reporting larger sizes are flagged as suspicious.
pub const MAX_DEVICE_SECTORS: u64 = 0x0010_0000_0000;

/// Default command timeout in iterations (~5 seconds at typical CPU speed)
pub const COMMAND_TIMEOUT_DEFAULT: u32 = 5_000_000;

/// Extended timeout for secure erase operations (~1 hour)
pub const COMMAND_TIMEOUT_ERASE: u32 = 3600_000_000;

/// Minimum interval between TRIM operations in microseconds (10ms)
/// Prevents DoS through excessive TRIM commands
pub const TRIM_RATE_LIMIT_INTERVAL_US: u64 = 10_000;

/// Port reset timeout in iterations (~1 second)
pub const PORT_RESET_TIMEOUT: u32 = 1_000_000;

/// Number of command slots per port (AHCI spec mandates 32)
pub const COMMAND_SLOTS_PER_PORT: usize = 32;

/// Command table size per slot in bytes
pub const COMMAND_TABLE_SLOT_SIZE: usize = 256;
