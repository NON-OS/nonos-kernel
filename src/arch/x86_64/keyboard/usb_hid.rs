//! USB HID Keyboard/Mouse Support

pub fn init_usb_hid() {
    // TODO: Initialize USB controller, register keyboard/mouse devices.
}

pub fn poll_usb_hid() {
    // TODO: Poll USB HID devices, parse reports, push InputEvent into input.rs
}

/// Parse USB HID report (keyboard)
pub fn parse_keyboard_report(report: &[u8; 8]) -> Option<u8> {
    // TODO: Map key code to ASCII or KeyCode
    None
}
