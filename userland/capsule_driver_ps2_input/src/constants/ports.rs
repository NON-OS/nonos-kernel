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

//! Port offsets and per-controller commands. The capsule never
//! sees absolute port numbers — the broker hands it a window
//! starting at port 0x60, and the offsets here are relative to
//! that base.
//!
//!   offset 0 = data port (0x60)
//!   offset 4 = status / command (0x64)

pub const DATA_OFFSET: u16 = 0;
pub const STATUS_OFFSET: u16 = 4;

// Keyboard-side command byte for "enable scanning" — sent through
// the data port, ack'd by the device with 0xFA.
pub const KBD_ENABLE_SCANNING: u8 = 0xF4;

// Capsule-side scancode ring. Sized for a comfortable depth at
// maximum sustained typing speed; a slow consumer drops events
// silently and bumps the dropped-events counter.
pub const RING_CAPACITY: usize = 256;
