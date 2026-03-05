// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! I2C HID subsystem for touchpads and other HID-over-I2C devices.
//!
//! This module provides support for precision touchpads connected via I2C HID protocol.
//! It handles device detection, initialization, and input processing.

extern crate alloc;

// Internal modules
pub mod descriptor;
pub mod device;
pub mod init;
pub mod poll;
pub mod protocol;
pub mod state;
pub mod touchpad;

// =============================================================================
// PUBLIC TYPE EXPORTS
// =============================================================================

pub use descriptor::{
    ContactFields, FieldLocation, HidDescriptor, ReportDescriptor, TouchpadLayout,
};
pub use device::{HidDeviceType, I2cHidDevice};
pub use touchpad::{TouchPoint, TouchpadDriver, TouchpadState};

pub fn get_supported_commands() -> &'static [protocol::HidCommand] {
    protocol::SUPPORTED_COMMANDS
}

pub fn get_register_address(reg: protocol::HidRegister) -> u16 {
    protocol::register_address(reg)
}

/// Check if a usage page/usage pair indicates a touchpad device
pub fn is_touchpad_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_DIGITIZER && usage == HID_USAGE_TOUCHPAD
}

/// Check if a usage page/usage pair indicates a touch screen device
pub fn is_touchscreen_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_DIGITIZER && usage == HID_USAGE_TOUCH_SCREEN
}

/// Check if a usage page/usage pair indicates a mouse device
pub fn is_mouse_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP && usage == HID_USAGE_MOUSE
}

/// Check if a usage page/usage pair indicates a keyboard device
pub fn is_keyboard_usage(usage_page: u16, usage: u8) -> bool {
    use protocol::*;
    usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP && usage == HID_USAGE_KEYBOARD
}

/// Get standard HID usage constants for touchpad fields
pub fn touchpad_field_usages() -> (u8, u8, u8, u8, u8, u8, u8) {
    use protocol::*;
    (
        HID_USAGE_TIP_SWITCH,
        HID_USAGE_CONTACT_ID,
        HID_USAGE_X,
        HID_USAGE_Y,
        HID_USAGE_CONTACT_COUNT,
        HID_USAGE_BUTTON_PRIMARY,
        HID_USAGE_BUTTON_SECONDARY,
    )
}

/// Get HID usage page constants
pub fn hid_usage_pages() -> (u16, u16, u16) {
    use protocol::*;
    (
        HID_USAGE_PAGE_DIGITIZER,
        HID_USAGE_PAGE_GENERIC_DESKTOP,
        HID_USAGE_PAGE_BUTTON,
    )
}

// Protocol types for external HID device handling
pub use protocol::{HidCommand, HidRegister};


// =============================================================================
// PUBLIC API
// =============================================================================

/// Initialize the I2C HID subsystem.
///
/// Detects I2C controllers and touchpad devices, initializes drivers.
/// Returns the number of touchpads found.
pub fn init() -> usize {
    init::init()
}

/// Set screen dimensions for cursor bounds.
///
/// Call this when screen resolution is known or changes.
pub fn set_screen_bounds(width: u32, height: u32) {
    state::set_screen_size(width, height);
}

/// Check if a touchpad is available.
pub fn is_available() -> bool {
    state::is_available()
}

/// Check if a touchpad is available (alias for compatibility).
pub fn touchpad_available() -> bool {
    state::is_available()
}

/// Check if touchpad is producing valid input.
pub fn touchpad_working() -> bool {
    state::is_available() && state::get_update_count() >= 5
}

/// Get current cursor position.
#[inline]
pub fn touchpad_position() -> (i32, i32) {
    state::get_cursor()
}

/// Check if left mouse button is pressed.
/// For touchpads, this always returns false (no physical buttons).
pub fn left_pressed() -> bool {
    false
}

/// Check if right mouse button is pressed.
/// For touchpads, this always returns false (no physical buttons).
pub fn right_pressed() -> bool {
    false
}

/// Poll touchpad for input.
///
/// Call this in the main loop to process touchpad input.
/// Returns true if cursor was updated or needs redraw.
pub fn poll() -> bool {
    poll::poll()
}

/// Get number of detected devices.
pub fn device_count() -> usize {
    state::device_count()
}

/// Get device info by index.
pub fn get_device_info(index: usize) -> Option<(HidDeviceType, u16, u16)> {
    let devices = state::DEVICES.lock();
    devices.get(index).map(|dev| {
        let desc = dev.hid_descriptor();
        (dev.device_type(), desc.vendor_id, desc.product_id)
    })
}

// =============================================================================
// DEBUG INFO
// =============================================================================

/// Debug information about the touchpad.
#[derive(Debug, Clone)]
pub struct TouchpadDebugInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub using_layout: bool,
    pub logical_max_x: i32,
    pub logical_max_y: i32,
    pub has_tip: bool,
    pub has_contact_id: bool,
    pub max_contacts: u8,
    pub update_count: u32,
}

/// Get debug info about the touchpad.
pub fn get_touchpad_debug_info() -> Option<TouchpadDebugInfo> {
    let devices = state::DEVICES.lock();

    for dev in devices.iter() {
        if matches!(dev.device_type(), HidDeviceType::Touchpad | HidDeviceType::Mouse) {
            let hid_desc = dev.hid_descriptor();
            let report_desc = dev.report_descriptor();
            let (max_x, max_y) = dev.touchpad_logical_max();

            return Some(TouchpadDebugInfo {
                vendor_id: hid_desc.vendor_id,
                product_id: hid_desc.product_id,
                using_layout: dev.is_using_layout(),
                logical_max_x: max_x,
                logical_max_y: max_y,
                has_tip: report_desc.has_tip,
                has_contact_id: report_desc.has_contact_id,
                max_contacts: report_desc.max_contact_count,
                update_count: state::get_update_count(),
            });
        }
    }

    None
}
