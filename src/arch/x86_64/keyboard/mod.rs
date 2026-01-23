// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub mod error;
pub mod input;
pub mod keymap;
pub mod layout;
mod manager;
pub mod ps2;
#[cfg(test)]
mod test;
pub mod types;
pub mod usb;

pub use manager::{
    handle_interrupt, has_ps2, has_usb, init, is_initialized, poll_usb,
};

pub use input::{
    drain_events, peek_event, pop_event, push_event, queue_len,
    DeviceId, InputDevice, InputError, InputEvent, InputEventKind,
    KeyEvent, MouseButton, MouseButtonEvent, MouseMoveEvent, MouseScrollEvent,
};

pub use keymap::{
    ascii_to_keycode, keycode_to_ascii, map_scan_code,
    KeyCode, KeyMapping, ModifierState, ScanCode,
};

pub use layout::{
    get_layout, get_layout_info, has_pending_dead_key, process_with_dead_key, set_layout,
    DeadKey, Layout, LayoutInfo,
};

pub use ps2::{
    set_leds as ps2_set_leds,
    Ps2Error, Ps2Result, Ps2Stats, TypematicConfig,
};

pub use usb::{
    device_count as usb_device_count, set_leds as usb_set_leds,
    HidDeviceType, LedState as UsbHidLedState, UsbHidError, UsbHidResult,
};
