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

//! `net.ip` op discriminants. New ops require a constant here, a
//! handler in `server::handlers`, and a wire schema entry in
//! `abi/wire.toml`; the dispatch table never routes by name.

pub const OP_HEALTHCHECK: u16 = 1;
pub const OP_GET_CONFIG: u16 = 2;
pub const OP_SET_CONFIG: u16 = 3;
pub const OP_SEND_PACKET: u16 = 4;
pub const OP_POLL_PACKET: u16 = 5;
pub const OP_ROUTE_ADD: u16 = 6;
pub const OP_ROUTE_CLEAR: u16 = 7;
