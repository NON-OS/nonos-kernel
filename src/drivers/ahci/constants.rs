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

//! AHCI register offsets and constants.

pub const HBA_CAP: u32 = 0x00;
pub const HBA_GHC: u32 = 0x04;
pub const HBA_IS: u32 = 0x08;
pub const HBA_PI: u32 = 0x0C;
pub const HBA_VS: u32 = 0x10;
pub const HBA_CAP2: u32 = 0x24;
pub const HBA_BOHC: u32 = 0x28;

pub const PORT_CLB: u32 = 0x00;
pub const PORT_CLBU: u32 = 0x04;
pub const PORT_FB: u32 = 0x08;
pub const PORT_FBU: u32 = 0x0C;
pub const PORT_IS: u32 = 0x10;
pub const PORT_IE: u32 = 0x14;
pub const PORT_CMD: u32 = 0x18;
pub const PORT_TFD: u32 = 0x20;
pub const PORT_SIG: u32 = 0x24;
pub const PORT_SSTS: u32 = 0x28;
pub const PORT_SCTL: u32 = 0x2C;
pub const PORT_SERR: u32 = 0x30;
pub const PORT_SACT: u32 = 0x34;
pub const PORT_CI: u32 = 0x38;

pub const CMD_ST: u32 = 1 << 0;
pub const CMD_FRE: u32 = 1 << 4;
pub const CMD_FR: u32 = 1 << 14;
pub const CMD_CR: u32 = 1 << 15;

pub const IS_TFES: u32 = 1 << 30;

pub const FIS_TYPE_REG_H2D: u8 = 0x27;

pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_CMD_DSM: u8 = 0x06;
pub const ATA_CMD_SECURITY_ERASE_PREPARE: u8 = 0xF3;
pub const ATA_CMD_SECURITY_ERASE_UNIT: u8 = 0xF4;

pub const DSM_TRIM: u8 = 0x01;

pub const MAX_DEVICE_SECTORS: u64 = 0x0010_0000_0000;
pub const COMMAND_TIMEOUT_DEFAULT: u32 = 5_000_000;
pub const COMMAND_TIMEOUT_ERASE: u32 = 3600_000_000;
pub const TRIM_RATE_LIMIT_INTERVAL_US: u64 = 10_000;
pub const PORT_RESET_TIMEOUT: u32 = 1_000_000;
pub const COMMAND_SLOTS_PER_PORT: usize = 32;
pub const COMMAND_TABLE_SLOT_SIZE: usize = 256;
