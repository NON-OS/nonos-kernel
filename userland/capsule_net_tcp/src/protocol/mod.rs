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

pub const MAGIC: u32 = 0x4E54_4350; // "NTCP"

pub const OP_HEALTHCHECK: u16 = 1;
pub const OP_LISTEN: u16 = 2;
pub const OP_CONNECT: u16 = 3;
pub const OP_ACCEPT: u16 = 4;
pub const OP_SEND: u16 = 5;
pub const OP_RECV: u16 = 6;
pub const OP_CLOSE: u16 = 7;
pub const OP_SHUTDOWN: u16 = 8;

pub const E_OK: u16 = 0;
pub const E_BAD_MAGIC: u16 = 1;
pub const E_BAD_VERSION: u16 = 2;
pub const E_BAD_OP: u16 = 3;
pub const E_BAD_LEN: u16 = 4;
pub const E_NO_SOCKET: u16 = 5;
pub const E_PORT_IN_USE: u16 = 6;
pub const E_REFUSED: u16 = 7;
pub const E_TIMEOUT: u16 = 8;
pub const E_RST: u16 = 9;
pub const E_CLOSED: u16 = 10;
pub const E_RX_EMPTY: u16 = 11;

pub const SERVICE_PORT: u32 = 4430;
pub const REPLY_PORT: u32 = 4431;
pub const SERVICE_NAME: &str = "net.tcp";
pub const REPLY_INBOX: &str = "endpoint.net.tcp.reply";

pub const SEGMENT_PAYLOAD_MAX: usize = 1460; // MTU 1500 - 20 IP - 20 TCP
pub const IPC_PAYLOAD_MAX: usize = SEGMENT_PAYLOAD_MAX + 64;
