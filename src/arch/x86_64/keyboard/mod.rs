// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

//! NØNOS Keyboard Subsystem
//!
//! ## Modules
//! - [`input`]: Input event queue and device abstraction
//! - [`keymap`]: Scan code to key code mapping
//! - [`layout`]: Keyboard layouts (US, UK, DE, etc.)
//! - [`ps2`]: PS/2 keyboard/mouse driver (8042 controller)
//! - [`usb_hid`]: USB HID keyboard/mouse driver

pub mod input;
pub mod keymap;
pub mod layout;
pub mod ps2;
pub mod usb_hid;

use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Initialization
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static PS2_PRESENT: AtomicBool = AtomicBool::new(false);
static USB_PRESENT: AtomicBool = AtomicBool::new(false);

/// Initializes the keyboard subsystem (PS/2 and USB HID)
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err("keyboard already initialized");
    }

    let mut has_keyboard = false;

    // Initialize PS/2
    if ps2::init().is_ok() {
        PS2_PRESENT.store(true, Ordering::Release);
        has_keyboard = true;
    }

    // Initialize USB HID
    if usb_hid::init().is_ok() && usb_hid::device_count() > 0 {
        USB_PRESENT.store(true, Ordering::Release);
        has_keyboard = true;
    }

    if !has_keyboard {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err("no keyboards detected");
    }

    Ok(())
}

/// Returns true if keyboard subsystem is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Returns true if PS/2 keyboard is present
pub fn has_ps2() -> bool {
    PS2_PRESENT.load(Ordering::Acquire)
}

/// Returns true if USB keyboard(s) are present
pub fn has_usb() -> bool {
    USB_PRESENT.load(Ordering::Acquire)
}

/// Handles PS/2 keyboard interrupt (IRQ1)
pub fn handle_interrupt() {
    ps2::handle_interrupt();
}

/// Polls USB keyboards (call periodically)
pub fn poll_usb() {
    if has_usb() {
        let _ = usb_hid::poll();
    }
}

// ============================================================================
// Re-exports
// ============================================================================

// Input queue and events
pub use input::{
    DeviceId, InputDevice, InputError, InputEvent, InputEventKind,
    KeyEvent, MouseMoveEvent, MouseButtonEvent, MouseScrollEvent, MouseButton,
    pop_event, push_event, drain_events, peek_event, queue_len,
};

// Keymap
pub use keymap::{
    KeyCode, KeyMapping, ModifierState, ScanCode,
    map_scan_code, keycode_to_ascii, ascii_to_keycode,
};

// Layout
pub use layout::{
    Layout, LayoutInfo, DeadKey,
    get_layout, set_layout, get_layout_info,
    has_pending_dead_key, process_with_dead_key,
};

// PS/2
pub use ps2::{
    Ps2Error, Ps2Result, DeviceType as Ps2DeviceType,
    LedState as Ps2LedState, TypematicConfig,
    set_leds as ps2_set_leds,
};

// USB HID
pub use usb_hid::{
    UsbHidError, UsbHidResult, HidDeviceType,
    LedState as UsbHidLedState,
    set_leds as usb_set_leds, device_count as usb_device_count,
};
