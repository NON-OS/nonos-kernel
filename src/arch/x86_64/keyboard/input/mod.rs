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

mod device;
mod error;
mod queue;
mod types;

pub use device::{
    device_count, list_devices, poll_all_devices, register_device,
    set_device_enabled, unregister_device, InputDevice, MAX_INPUT_DEVICES,
};
pub use error::{InputError, InputErrorCode, InputResult};
pub use queue::{
    clear, configure, drain_events, drain_events_filtered, dropped_events,
    get_config, is_empty, is_shutdown, peek_event, peek_event_filtered,
    pop_event, pop_event_filtered, push_event, queue_len, register_waiter,
    restart, shutdown, stats, total_events, unregister_waiter,
    QueueConfig, QueueStats, WaitHandle,
    DEFAULT_MAX_QUEUE_SIZE, DEFAULT_PRESSURE_THRESHOLD,
    MAX_ALLOWED_QUEUE_SIZE, MAX_COALESCE_COUNT,
};
pub use types::{
    DeviceId, EventFilter, EventPriority, InputEvent, InputEventKind,
    KeyEvent, Modifiers, MouseButton, MouseButtonEvent, MouseMoveEvent, MouseScrollEvent,
};

use core::sync::atomic::{AtomicU64, Ordering};

static TIMESTAMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn get_timestamp() -> u64 {
    TIMESTAMP_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub fn push_key_press(scan_code: u8) {
    let _ = push_event(InputEvent::key_press(scan_code));
}

pub fn push_key_release(scan_code: u8) {
    let _ = push_event(InputEvent::key_release(scan_code));
}

pub fn push_mouse_move(dx: i16, dy: i16) {
    let _ = push_event(InputEvent::mouse_move(dx, dy));
}

pub fn push_mouse_button(button: u8, pressed: bool) {
    let _ = push_event(InputEvent::mouse_button(button, pressed));
}

pub fn push_mouse_scroll(delta: i8) {
    let _ = push_event(InputEvent::mouse_scroll(delta));
}
