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

pub const REG_MAC0: u16 = 0x00;
pub const REG_TXSTATUS0: u16 = 0x10;
pub const REG_TXADDR0: u16 = 0x20;
pub const REG_RBSTART: u16 = 0x30;
pub const REG_CMD: u16 = 0x37;
pub const REG_CAPR: u16 = 0x38;
pub const REG_IMR: u16 = 0x3C;
pub const REG_ISR: u16 = 0x3E;
pub const REG_TCR: u16 = 0x40;
pub const REG_RCR: u16 = 0x44;
pub const REG_MSR: u16 = 0x58;

pub const CMD_RESET: u8 = 0x10;
pub const CMD_RX_ENABLE: u8 = 0x08;
pub const CMD_TX_ENABLE: u8 = 0x04;
pub const CMD_RX_BUF_EMPTY: u8 = 0x01;
pub const MSR_LINK_BAD: u8 = 0x04;

pub const ISR_RX_OK: u16 = 0x0001;
pub const ISR_RX_ERR: u16 = 0x0002;
pub const ISR_TX_OK: u16 = 0x0004;
pub const ISR_TX_ERR: u16 = 0x0008;
pub const ISR_RX_OVERFLOW: u16 = 0x0010;
pub const ISR_RX_FIFO_OVERFLOW: u16 = 0x0040;
pub const ISR_ENABLED: u16 =
    ISR_RX_OK | ISR_RX_ERR | ISR_TX_OK | ISR_TX_ERR | ISR_RX_OVERFLOW | ISR_RX_FIFO_OVERFLOW;

pub const RX_STATUS_OK: u16 = 0x0001;
pub const RCR_ACCEPT_PHYS: u32 = 1 << 1;
pub const RCR_ACCEPT_MULTI: u32 = 1 << 2;
pub const RCR_ACCEPT_BCAST: u32 = 1 << 3;
pub const RCR_WRAP: u32 = 1 << 7;
pub const RCR_MXDMA_UNLIMITED: u32 = 7 << 8;
pub const TCR_MXDMA_UNLIMITED: u32 = 7 << 8;

pub const TX_STATUS_OK: u32 = 1 << 15;
pub const TX_STATUS_UNDERRUN: u32 = 1 << 14;
pub const TX_STATUS_ABORT: u32 = 1 << 30;
