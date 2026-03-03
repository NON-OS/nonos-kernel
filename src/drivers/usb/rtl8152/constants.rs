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
pub const REALTEK_VENDOR_ID: u16 = 0x0BDA;
pub const RTL8152_PRODUCT_IDS: &[u16] = &[
    0x8050, 0x8152, 0x8153, 0x8155, 0x8156, 0x8158, 0x8151, 0x8171,
];

pub const HAMA_VENDOR_ID: u16 = 0x1A81;
pub const HAMA_PRODUCT_IDS: &[u16] = &[0x4001, 0x4002, 0x4003, 0x4004, 0x4005, 0x4006];

pub const LENOVO_VENDOR_ID: u16 = 0x17EF;
pub const LENOVO_PRODUCT_IDS: &[u16] = &[0x7205, 0x720A, 0x720B, 0x720C, 0x7214, 0x3062, 0x3069];

pub const SAMSUNG_VENDOR_ID: u16 = 0x04E8;
pub const SAMSUNG_PRODUCT_IDS: &[u16] = &[0xA101, 0xA102, 0xA103];

pub const LINKSYS_VENDOR_ID: u16 = 0x13B1;
pub const LINKSYS_PRODUCT_IDS: &[u16] = &[0x0041, 0x0042];

pub const NVIDIA_VENDOR_ID: u16 = 0x0955;
pub const NVIDIA_PRODUCT_IDS: &[u16] = &[0x09FF];

pub const TPLINK_VENDOR_ID: u16 = 0x2357;
pub const TPLINK_PRODUCT_IDS: &[u16] = &[0x0601, 0x0602, 0x0600];

pub const ASIX_VENDOR_ID: u16 = 0x0B95;
pub const ASIX_PRODUCT_IDS: &[u16] = &[0x1790, 0x178A, 0x7720, 0x772A, 0x772B, 0x772D, 0x7E2B];

pub const DLINK_VENDOR_ID: u16 = 0x2001;
pub const DLINK_PRODUCT_IDS: &[u16] = &[0x4A00, 0x1A00, 0x1A02, 0x3C05];

pub const BELKIN_VENDOR_ID: u16 = 0x050D;
pub const BELKIN_PRODUCT_IDS: &[u16] = &[0x5055, 0x0121];

pub const APPLE_VENDOR_ID: u16 = 0x05AC;
pub const APPLE_PRODUCT_IDS: &[u16] = &[0x1402];

pub const MICROSOFT_VENDOR_ID: u16 = 0x045E;
pub const MICROSOFT_PRODUCT_IDS: &[u16] = &[0x07C6, 0x0927];

pub const ANKER_VENDOR_ID: u16 = 0x291A;
pub const ANKER_PRODUCT_IDS: &[u16] = &[0x8352, 0x8153];

pub const UGREEN_VENDOR_ID: u16 = 0x2A37;
pub const UGREEN_PRODUCT_IDS: &[u16] = &[0x0100, 0x0101];

pub const GENERIC_USB_ETH_CLASS: u8 = 0xFF;

pub const RTL_REG_MAC: u16 = 0xC000;
pub const RTL_REG_CONFIG: u16 = 0xC002;
pub const RTL_REG_CTRL: u16 = 0xC010;
pub const RTL_REG_STATUS: u16 = 0xC018;
pub const RTL_REG_RX_CFG: u16 = 0xC010;
pub const RTL_REG_TX_CFG: u16 = 0xC012;
pub const RTL_REG_PHY_CTRL: u16 = 0xC020;
pub const RTL_REG_PHY_STATUS: u16 = 0xC022;

pub const RTL_CTRL_RESET: u8 = 0x10;
pub const RTL_CTRL_START: u8 = 0x01;
pub const RTL_CTRL_STOP: u8 = 0x00;

pub const RTL_RX_ENABLE: u16 = 0x0001;
pub const RTL_TX_ENABLE: u16 = 0x0001;
pub const RTL_RX_ACCEPT_ALL: u16 = 0x000F;
pub const RTL_RX_ACCEPT_BROADCAST: u16 = 0x0008;
pub const RTL_RX_ACCEPT_MULTICAST: u16 = 0x0004;
pub const RTL_RX_ACCEPT_PHYS: u16 = 0x0002;

pub const RTL_VENDOR_READ: u8 = 0xC0;
pub const RTL_VENDOR_WRITE: u8 = 0x40;
pub const RTL_REQ_GET_REGS: u8 = 0x05;
pub const RTL_REQ_SET_REGS: u8 = 0x05;

pub const RTL_OCP_BASE: u16 = 0xE000;
pub const RTL_PLA_BASE: u16 = 0xC000;
pub const RTL_USB_BASE: u16 = 0xB000;

pub const RTL8152_MTU: usize = 1500;
pub const RTL8152_RX_BUF_SIZE: usize = 16384;
pub const RTL8152_TX_BUF_SIZE: usize = 2048;
