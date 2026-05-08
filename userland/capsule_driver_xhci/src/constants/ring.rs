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

//! Ring sizing. xHCI TRBs are 16 bytes. The command ring carries
//! `COMMAND_RING_TRBS - 1` usable slots plus one Link TRB; the
//! event ring uses one segment with `EVENT_RING_SEGMENT_TRBS`
//! entries. Capacity is intentionally small for v1; the next
//! slice grows it once the boot path proves out.

pub const TRB_BYTES: usize = 16;

pub const COMMAND_RING_TRBS: usize = 64;
pub const EVENT_RING_SEGMENT_TRBS: usize = 64;
pub const EVENT_RING_SEGMENT_TABLE_ENTRIES: usize = 1;
