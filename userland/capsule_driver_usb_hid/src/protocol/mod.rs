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

mod decode;
mod encode;
mod errno;
mod header;
mod limits;
mod ops;

pub use decode::parse;
pub use encode::{response_header, write_status};
pub use errno::{E_BAD_OP, E_INVAL, E_NO_HID};
pub use header::{Request, HDR_LEN};
pub use limits::{
    CONFIG_DESCRIPTOR_MAX, HID_BINDING_WIRE_LEN, IPC_PAYLOAD_MAX, KEY_EVENT_WIRE_LEN,
    KEY_REPORT_LEN, MAX_EVENTS, MAX_HID_BINDINGS, MOUSE_EVENT_WIRE_LEN, MOUSE_REPORT_MAX,
    MOUSE_REPORT_MIN, STATUS_LEN,
};
pub use ops::{
    OP_FEED_KEYBOARD_REPORT, OP_FEED_MOUSE_REPORT, OP_GET_STATE, OP_HEALTHCHECK, OP_POLL_KEYS,
    OP_POLL_MOUSE, OP_PROBE_CONFIG,
};
