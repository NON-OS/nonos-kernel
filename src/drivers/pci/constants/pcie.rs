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

pub const PCIE_TYPE_ENDPOINT: u8 = 0x0;
pub const PCIE_TYPE_LEGACY_ENDPOINT: u8 = 0x1;
pub const PCIE_TYPE_ROOT_PORT: u8 = 0x4;
pub const PCIE_TYPE_UPSTREAM_PORT: u8 = 0x5;
pub const PCIE_TYPE_DOWNSTREAM_PORT: u8 = 0x6;
pub const PCIE_TYPE_PCIE_TO_PCI_BRIDGE: u8 = 0x7;
pub const PCIE_TYPE_PCI_TO_PCIE_BRIDGE: u8 = 0x8;
pub const PCIE_TYPE_ROOT_COMPLEX_ENDPOINT: u8 = 0x9;
pub const PCIE_TYPE_ROOT_COMPLEX_EVENT_COLLECTOR: u8 = 0xA;

pub const PCIE_LINK_SPEED_2_5GT: u8 = 0x1;
pub const PCIE_LINK_SPEED_5GT: u8 = 0x2;
pub const PCIE_LINK_SPEED_8GT: u8 = 0x3;
pub const PCIE_LINK_SPEED_16GT: u8 = 0x4;
pub const PCIE_LINK_SPEED_32GT: u8 = 0x5;
pub const PCIE_LINK_SPEED_64GT: u8 = 0x6;

pub const PCIE_LINK_WIDTH_X1: u8 = 0x01;
pub const PCIE_LINK_WIDTH_X2: u8 = 0x02;
pub const PCIE_LINK_WIDTH_X4: u8 = 0x04;
pub const PCIE_LINK_WIDTH_X8: u8 = 0x08;
pub const PCIE_LINK_WIDTH_X12: u8 = 0x0C;
pub const PCIE_LINK_WIDTH_X16: u8 = 0x10;
pub const PCIE_LINK_WIDTH_X32: u8 = 0x20;

pub const BRIDGE_CTL_PARITY_ERROR_RESPONSE: u16 = 1 << 0;
pub const BRIDGE_CTL_SERR_ENABLE: u16 = 1 << 1;
pub const BRIDGE_CTL_ISA_ENABLE: u16 = 1 << 2;
pub const BRIDGE_CTL_VGA_ENABLE: u16 = 1 << 3;
pub const BRIDGE_CTL_VGA_16BIT: u16 = 1 << 4;
pub const BRIDGE_CTL_MASTER_ABORT_MODE: u16 = 1 << 5;
pub const BRIDGE_CTL_SECONDARY_BUS_RESET: u16 = 1 << 6;
pub const BRIDGE_CTL_FAST_B2B_ENABLE: u16 = 1 << 7;
pub const BRIDGE_CTL_PRIMARY_DISCARD_TIMER: u16 = 1 << 8;
pub const BRIDGE_CTL_SECONDARY_DISCARD_TIMER: u16 = 1 << 9;
pub const BRIDGE_CTL_DISCARD_TIMER_STATUS: u16 = 1 << 10;
pub const BRIDGE_CTL_DISCARD_TIMER_SERR_ENABLE: u16 = 1 << 11;
