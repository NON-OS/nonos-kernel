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
pub const CDC_CLASS: u8 = 0x02;
pub const CDC_DATA_CLASS: u8 = 0x0A;
pub const CDC_SUBCLASS_ECM: u8 = 0x06;
pub const CDC_SUBCLASS_NCM: u8 = 0x0D;

pub const CDC_SET_ETHERNET_MULTICAST: u8 = 0x40;
pub const CDC_SET_ETHERNET_PM_FILTER: u8 = 0x41;
pub const CDC_GET_ETHERNET_PM_FILTER: u8 = 0x42;
pub const CDC_SET_ETHERNET_PKT_FILTER: u8 = 0x43;
pub const CDC_GET_ETHERNET_STATS: u8 = 0x44;
pub const CDC_SET_NTB_INPUT_SIZE: u8 = 0x86;
pub const CDC_GET_NTB_PARAMETERS: u8 = 0x80;

pub const PACKET_TYPE_PROMISCUOUS: u16 = 0x0001;
pub const PACKET_TYPE_ALL_MULTICAST: u16 = 0x0002;
pub const PACKET_TYPE_DIRECTED: u16 = 0x0004;
pub const PACKET_TYPE_BROADCAST: u16 = 0x0008;
pub const PACKET_TYPE_MULTICAST: u16 = 0x0010;
