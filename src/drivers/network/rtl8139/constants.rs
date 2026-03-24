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

pub const RTL8139_VENDOR_ID: u16 = 0x10EC;
pub const RTL8139_DEVICE_ID: u16 = 0x8139;

pub const REG_MAC0: u16 = 0x00;
pub const REG_MAR0: u16 = 0x08;
pub const REG_TXSTATUS0: u16 = 0x10;
pub const REG_TXADDR0: u16 = 0x20;
pub const REG_RXBUF: u16 = 0x30;
pub const REG_CMD: u16 = 0x37;
pub const REG_CAPR: u16 = 0x38;
pub const REG_CBR: u16 = 0x3A;
pub const REG_IMR: u16 = 0x3C;
pub const REG_ISR: u16 = 0x3E;
pub const REG_TCR: u16 = 0x40;
pub const REG_RCR: u16 = 0x44;
pub const REG_CONFIG1: u16 = 0x52;

pub const CMD_RESET: u8 = 0x10;
pub const CMD_RX_ENABLE: u8 = 0x08;
pub const CMD_TX_ENABLE: u8 = 0x04;

pub const TCR_IFG_STANDARD: u32 = 3 << 24;
pub const TCR_MXDMA_2048: u32 = 7 << 8;

pub const RCR_ACCEPT_ALL: u32 = 0x0F;
pub const RCR_WRAP: u32 = 1 << 7;
pub const RCR_MXDMA_UNLIM: u32 = 7 << 8;
pub const RCR_RBLEN_64K: u32 = 3 << 11;

pub const ISR_ROK: u16 = 0x0001;
pub const ISR_TOK: u16 = 0x0004;

pub const RX_BUF_SIZE: usize = 64 * 1024 + 16;
pub const TX_BUF_SIZE: usize = 2048;
pub const NUM_TX_BUFFERS: usize = 4;
