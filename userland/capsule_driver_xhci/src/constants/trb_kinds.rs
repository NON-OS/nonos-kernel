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

//! TRB type discriminants used in P0. The wider command/transfer
//! and event surface lands with P1 (slot enable, address device).

pub const TRB_TYPE_LINK: u32 = 6;
pub const TRB_TYPE_NOOP_CMD: u32 = 23;
pub const TRB_TYPE_CMD_COMPLETION_EVENT: u32 = 33;
