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

pub const MAGIC: u32 = 0x4E44_4843; // "NDHC"

pub const OP_HEALTHCHECK: u16 = 1;
pub const OP_LEASE_REQUEST: u16 = 2;
pub const OP_LEASE_STATUS: u16 = 3;
pub const OP_LEASE_RELEASE: u16 = 4;
pub const OP_LEASE_RENEW: u16 = 5;

pub const E_OK: u16 = 0;
pub const E_BAD_MAGIC: u16 = 1;
pub const E_BAD_VERSION: u16 = 2;
pub const E_BAD_OP: u16 = 3;
pub const E_BAD_LEN: u16 = 4;
pub const E_NO_LINK: u16 = 5;
pub const E_TIMEOUT: u16 = 6;
pub const E_NAK: u16 = 7;
pub const E_BUSY: u16 = 8;

pub const SERVICE_PORT: u32 = 4440;
pub const REPLY_PORT: u32 = 4441;
pub const SERVICE_NAME: &str = "net.dhcp.client";
pub const REPLY_INBOX: &str = "endpoint.net.dhcp.client.reply";
