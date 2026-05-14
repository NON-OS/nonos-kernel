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

//! Wire-form sizing constants. The v1 envelope is 20 bytes;
//! `STATUS_LEN` is the leading i32 every reply carries; the rest
//! is per-op payload sized below.

pub const STATUS_LEN: usize = 4;

/// Max events one poll reply carries. Tuned to fit comfortably
/// inside the IPC inline payload limit (256 events * 3 bytes per
/// event = 768 bytes), well under the kernel cap.
pub const MAX_POLL_EVENTS: usize = 256;

/// Per-event wire form: u8 scancode + u8 flags + u8 reserved.
pub const EVENT_WIRE_LEN: usize = 3;
pub const MOUSE_EVENT_WIRE_LEN: usize = 8;

/// `get_state` reply payload: keyboard counters followed by AUX
/// mouse counters:
/// kbd events_seen, kbd events_dropped, parity_errors,
/// timeout_errors, mouse events_seen, mouse events_dropped,
/// mouse sync_errors.
pub const STATE_PAYLOAD_LEN: usize = 8 * 7;

/// `controller_status` reply payload: status byte, decoded
/// flags, keyboard ring cursors, mouse enable state, and queued
/// mouse event count.
pub const CONTROLLER_STATUS_PAYLOAD_LEN: usize = 28;

/// Poll reply prefix: status (i32) + count (u32).
pub const POLL_PAYLOAD_PREFIX_LEN: usize = STATUS_LEN + 4;
pub const MOUSE_POLL_PAYLOAD_PREFIX_LEN: usize = STATUS_LEN + 4;
