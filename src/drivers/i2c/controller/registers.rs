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

pub const IC_CON: u64 = 0x00;
pub const IC_TAR: u64 = 0x04;
pub const _IC_SAR: u64 = 0x08;
pub const _IC_HS_MADDR: u64 = 0x0C;
pub const IC_DATA_CMD: u64 = 0x10;
pub const IC_SS_SCL_HCNT: u64 = 0x14;
pub const IC_SS_SCL_LCNT: u64 = 0x18;
pub const IC_FS_SCL_HCNT: u64 = 0x1C;
pub const IC_FS_SCL_LCNT: u64 = 0x20;
pub const IC_HS_SCL_HCNT: u64 = 0x24;
pub const IC_HS_SCL_LCNT: u64 = 0x28;
pub const _IC_INTR_STAT: u64 = 0x2C;
pub const IC_INTR_MASK: u64 = 0x30;
pub const IC_RAW_INTR_STAT: u64 = 0x34;
pub const IC_RX_TL: u64 = 0x38;
pub const IC_TX_TL: u64 = 0x3C;
pub const IC_CLR_INTR: u64 = 0x40;
pub const _IC_CLR_RX_UNDER: u64 = 0x44;
pub const _IC_CLR_RX_OVER: u64 = 0x48;
pub const _IC_CLR_TX_OVER: u64 = 0x4C;
pub const _IC_CLR_RD_REQ: u64 = 0x50;
pub const IC_CLR_TX_ABRT: u64 = 0x54;
pub const _IC_CLR_RX_DONE: u64 = 0x58;
pub const _IC_CLR_ACTIVITY: u64 = 0x5C;
pub const IC_CLR_STOP_DET: u64 = 0x60;
pub const _IC_CLR_START_DET: u64 = 0x64;
pub const _IC_CLR_GEN_CALL: u64 = 0x68;
pub const IC_ENABLE: u64 = 0x6C;
pub const IC_STATUS: u64 = 0x70;
pub const IC_TXFLR: u64 = 0x74;
pub const IC_RXFLR: u64 = 0x78;
pub const IC_SDA_HOLD: u64 = 0x7C;
pub const IC_TX_ABRT_SOURCE: u64 = 0x80;
pub const _IC_SLV_DATA_NACK_ONLY: u64 = 0x84;
pub const _IC_DMA_CR: u64 = 0x88;
pub const _IC_DMA_TDLR: u64 = 0x8C;
pub const _IC_DMA_RDLR: u64 = 0x90;
pub const _IC_SDA_SETUP: u64 = 0x94;
pub const _IC_ACK_GENERAL_CALL: u64 = 0x98;
pub const IC_ENABLE_STATUS: u64 = 0x9C;
pub const IC_FS_SPKLEN: u64 = 0xA0;
pub const IC_HS_SPKLEN: u64 = 0xA4;
pub const _IC_CLR_RESTART_DET: u64 = 0xA8;
pub const IC_COMP_PARAM_1: u64 = 0xF4;
pub const _IC_COMP_VERSION: u64 = 0xF8;
pub const IC_COMP_TYPE: u64 = 0xFC;

pub const IC_CON_MASTER_MODE: u32 = 1 << 0;
pub const IC_CON_SPEED_SS: u32 = 1 << 1;
pub const IC_CON_SPEED_FS: u32 = 2 << 1;
pub const IC_CON_SPEED_HS: u32 = 3 << 1;
pub const IC_CON_SPEED_MASK: u32 = 3 << 1;
pub const _IC_CON_10BITADDR_SLAVE: u32 = 1 << 3;
pub const _IC_CON_10BITADDR_MASTER: u32 = 1 << 4;
pub const IC_CON_RESTART_EN: u32 = 1 << 5;
pub const IC_CON_SLAVE_DISABLE: u32 = 1 << 6;
pub const _IC_CON_STOP_DET_IFADDRESSED: u32 = 1 << 7;
pub const _IC_CON_TX_EMPTY_CTRL: u32 = 1 << 8;
pub const _IC_CON_RX_FIFO_FULL_HLD_CTRL: u32 = 1 << 9;

pub const IC_DATA_CMD_READ: u32 = 1 << 8;
pub const IC_DATA_CMD_STOP: u32 = 1 << 9;
pub const _IC_DATA_CMD_RESTART: u32 = 1 << 10;

pub const _IC_INTR_RX_UNDER: u32 = 1 << 0;
pub const _IC_INTR_RX_OVER: u32 = 1 << 1;
pub const _IC_INTR_RX_FULL: u32 = 1 << 2;
pub const _IC_INTR_TX_OVER: u32 = 1 << 3;
pub const _IC_INTR_TX_EMPTY: u32 = 1 << 4;
pub const _IC_INTR_RD_REQ: u32 = 1 << 5;
pub const IC_INTR_TX_ABRT: u32 = 1 << 6;
pub const _IC_INTR_RX_DONE: u32 = 1 << 7;
pub const _IC_INTR_ACTIVITY: u32 = 1 << 8;
pub const IC_INTR_STOP_DET: u32 = 1 << 9;
pub const _IC_INTR_START_DET: u32 = 1 << 10;
pub const _IC_INTR_GEN_CALL: u32 = 1 << 11;
pub const _IC_INTR_RESTART_DET: u32 = 1 << 12;
pub const _IC_INTR_MST_ON_HOLD: u32 = 1 << 13;

pub const _IC_STATUS_ACTIVITY: u32 = 1 << 0;
pub const _IC_STATUS_TFNF: u32 = 1 << 1;
pub const IC_STATUS_TFE: u32 = 1 << 2;
pub const IC_STATUS_RFNE: u32 = 1 << 3;
pub const _IC_STATUS_RFF: u32 = 1 << 4;
pub const IC_STATUS_MST_ACTIVITY: u32 = 1 << 5;
pub const _IC_STATUS_SLV_ACTIVITY: u32 = 1 << 6;

pub const IC_ENABLE_ENABLE: u32 = 1 << 0;
pub const _IC_ENABLE_ABORT: u32 = 1 << 1;
pub const _IC_ENABLE_TX_CMD_BLOCK: u32 = 1 << 2;

pub const _IC_TAR_10BITADDR_MASTER: u32 = 1 << 12;

pub const TIMEOUT_US: u64 = 100_000;
pub const DW_IC_COMP_TYPE_VALUE: u32 = 0x44570140;
pub const I2C_MMIO_SIZE: usize = 0x1000;
