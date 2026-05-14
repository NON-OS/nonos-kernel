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

pub const STATUS_LEN: usize = 4;
pub const CONFIG_DESCRIPTOR_MAX: usize = 512;
pub const IPC_PAYLOAD_MAX: usize = 768;
pub const HID_BINDING_WIRE_LEN: usize = 8;
pub const MAX_HID_BINDINGS: usize = 8;
pub const KEY_REPORT_LEN: usize = 8;
pub const MOUSE_REPORT_MIN: usize = 3;
pub const MOUSE_REPORT_MAX: usize = 4;
pub const MAX_EVENTS: usize = 16;
pub const KEY_EVENT_WIRE_LEN: usize = 8;
pub const MOUSE_EVENT_WIRE_LEN: usize = 8;
