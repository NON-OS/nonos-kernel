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

//! RFC 2131 / 2132 wire constants. The fixed BOOTP region is 240
//! bytes; options follow, terminated by the END marker (0xFF).

pub const OP_REQUEST: u8 = 1;

pub const HTYPE_ETHERNET: u8 = 1;
pub const HLEN_ETHERNET: u8 = 6;

pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

pub const HEADER_LEN: usize = 240;

pub const FIELD_OP: usize = 0;
pub const FIELD_HTYPE: usize = 1;
pub const FIELD_HLEN: usize = 2;
pub const FIELD_XID: usize = 4;
pub const FIELD_FLAGS: usize = 10;
pub const FIELD_CIADDR: usize = 12;
pub const FIELD_YIADDR: usize = 16;
pub const FIELD_CHADDR: usize = 28;
pub const FIELD_COOKIE: usize = 236;

pub const FLAG_BROADCAST: u16 = 0x8000;

pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_IDENTIFIER: u8 = 54;
pub const OPT_PARAMETER_LIST: u8 = 55;
pub const OPT_END: u8 = 0xFF;

pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPACK: u8 = 5;
pub const DHCPNAK: u8 = 6;
pub const DHCPRELEASE: u8 = 7;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
