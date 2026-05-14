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

//! Wire-side maximums for the `net.ip` envelope. IPv4 caps the
//! payload at 1480 (1500 MTU - 20 header); the IPC payload allows
//! a margin so a caller can wrap the full datagram in one v2
//! envelope without splitting.

pub const IPV4_MTU: usize = 1500;
pub const IPV4_PAYLOAD_MAX: usize = 1480;
pub const IPC_PAYLOAD_MAX: usize = IPV4_MTU + 64;
