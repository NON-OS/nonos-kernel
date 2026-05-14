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

pub const MAGIC: u32 = 0x4E53_4B54; // "NSKT"

pub const OP_HEALTHCHECK: u16 = 1;
pub const OP_SOCKET: u16 = 2;
pub const OP_BIND: u16 = 3;
pub const OP_LISTEN: u16 = 4;
pub const OP_ACCEPT: u16 = 5;
pub const OP_CONNECT: u16 = 6;
pub const OP_SEND: u16 = 7;
pub const OP_RECV: u16 = 8;
pub const OP_CLOSE: u16 = 9;
pub const OP_GETSOCKOPT: u16 = 10;
pub const OP_SETSOCKOPT: u16 = 11;

pub const E_OK: u16 = 0;
pub const E_BAD_MAGIC: u16 = 1;
pub const E_BAD_VERSION: u16 = 2;
pub const E_BAD_OP: u16 = 3;
pub const E_BAD_LEN: u16 = 4;
pub const E_NO_HANDLE: u16 = 5;
pub const E_NO_TRANSPORT: u16 = 6;
pub const E_TABLE_FULL: u16 = 7;
pub const E_BAD_FAMILY: u16 = 8;
pub const E_BAD_KIND: u16 = 9;
pub const E_NOT_BOUND: u16 = 10;
pub const E_NOT_LISTENING: u16 = 11;
pub const E_NOT_CONNECTED: u16 = 12;
pub const E_RX_EMPTY: u16 = 13;
pub const E_REFUSED: u16 = 14;
pub const E_TIMEOUT: u16 = 15;

pub const SERVICE_PORT: u32 = 4460;
pub const REPLY_PORT: u32 = 4461;
pub const SERVICE_NAME: &str = "net.sockets";
pub const REPLY_INBOX: &str = "endpoint.net.sockets.reply";
