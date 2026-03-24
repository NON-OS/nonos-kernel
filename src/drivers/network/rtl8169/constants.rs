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

pub const RTL8169_VENDOR_ID: u16 = 0x10EC;
pub const RTL8169_DEVICE_ID: u16 = 0x8169;
pub const RTL8168_DEVICE_ID: u16 = 0x8168;

pub const REG_MAC0: u32 = 0x00;
pub const REG_TXDESC_ADDR_LO: u32 = 0x20;
pub const REG_TXDESC_ADDR_HI: u32 = 0x24;
pub const REG_CMD: u32 = 0x37;
pub const REG_TX_POLL: u32 = 0x38;
pub const REG_IMR: u32 = 0x3C;
pub const REG_ISR: u32 = 0x3E;
pub const REG_TX_CONFIG: u32 = 0x40;
pub const REG_RX_CONFIG: u32 = 0x44;
pub const REG_RMS: u32 = 0xDA;
pub const REG_RXDESC_ADDR_LO: u32 = 0xE4;
pub const REG_RXDESC_ADDR_HI: u32 = 0xE8;

pub const CMD_RESET: u8 = 0x10;
pub const CMD_RX_ENABLE: u8 = 0x08;
pub const CMD_TX_ENABLE: u8 = 0x04;

pub const TX_POLL_HPQ: u8 = 0x80;

pub const TX_CONFIG_IFG: u32 = 3 << 24;
pub const TX_CONFIG_DMA: u32 = 7 << 8;

pub const RX_CONFIG_ACCEPT_ALL: u32 = 0x0F;
pub const RX_CONFIG_NO_WRAP: u32 = 0;
pub const RX_CONFIG_DMA: u32 = 7 << 8;
pub const RX_CONFIG_MAXDMA: u32 = 7 << 13;

pub const ISR_ROK: u16 = 0x0001;
pub const ISR_TOK: u16 = 0x0004;

pub const DESC_OWN: u32 = 1 << 31;
pub const DESC_EOR: u32 = 1 << 30;
pub const DESC_FS: u32 = 1 << 29;
pub const DESC_LS: u32 = 1 << 28;

pub const NUM_RX_DESC: usize = 64;
pub const NUM_TX_DESC: usize = 64;
pub const BUFFER_SIZE: usize = 2048;
