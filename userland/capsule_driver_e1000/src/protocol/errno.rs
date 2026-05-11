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

//! Status codes carried in the first four payload bytes. Mirror
//! Linux errnos so the kernel-side network client uses the same
//! errno-to-error mapper for every NIC capsule. `E_AGAIN` is the
//! `rx_packet` "queue empty" path; the client surfaces it as
//! `RxQueueEmpty` rather than as a hard error.

pub const E_INVAL: i32 = -22;
pub const E_IO: i32 = -5;
pub const E_AGAIN: i32 = -11;
pub const E_MSGSIZE: i32 = -90;
