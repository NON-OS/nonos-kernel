//! USB HID Keyboard/Mouse Support 

use crate::arch::x86_64::keyboard::input::{push_event, InputEvent};
use alloc::vec::Vec;

/// Initialize USB HID subsystem and register keyboard/mouse devices.
pub fn init_usb_hid() -> Result<(), &'static str> {
    // Initialize USB controllers and enumerate devices.
    crate::drivers::nonos_xhci::init_xhci()?;
    crate::drivers::nonos_usb::init_usb()?;
    Ok(())
}

/// Poll all USB HID devices, parse reports, and push InputEvent into input.rs.
pub fn poll_usb_hid() -> Result<(), &'static str> {
    let usb_mgr = crate::drivers::nonos_usb::get_manager()
        .ok_or("USB manager not initialized")?;

    for dev in usb_mgr.devices() {
        // Only poll interfaces that are HID class (0x03)
        if let Some(cfg) = &dev.active_config {
            for iface in &cfg.interfaces {
                let class = iface.iface.b_interface_class;
                let proto = iface.iface.b_interface_protocol;
                if class == 0x03 && proto == 0x01 {
                    // HID Keyboard
                    if let Some(report) = poll_hid_keyboard_report(&dev, iface) {
                        if let Some(keycode) = parse_keyboard_report(&report) {
                            push_event(InputEvent::KeyPress(keycode));
                        }
                    }
                } else if class == 0x03 && proto == 0x02 {
                    // HID Mouse
                    if let Some(report) = poll_hid_mouse_report(&dev, iface) {
                        if let Some((dx, dy, buttons)) = parse_mouse_report(&report) {
                            push_event(InputEvent::MouseMove { dx, dy });
                            for (btn, pressed) in buttons.iter().enumerate() {
                                push_event(InputEvent::MouseButton { button: btn as u8, pressed: *pressed });
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Poll HID keyboard report from the appropriate endpoint.
fn poll_hid_keyboard_report(
    dev: &crate::drivers::nonos_usb::UsbDevice,
    iface: &crate::drivers::nonos_usb::UsbInterfaceInfo,
) -> Option<[u8; 8]> {
    // Find interrupt IN endpoint for keyboard
    if let Some(ep) = iface.endpoints.iter().find(|ep| (ep.b_endpoint_address & 0x80) != 0) {
        let mut report = [0u8; 8];
        // Use the USB stack to poll the endpoint.
        if crate::drivers::nonos_usb::poll_endpoint(
            dev.slot_id,
            ep.b_endpoint_address,
            &mut report,
        ).is_ok() {
            return Some(report);
        }
    }
    None
}

/// Poll HID mouse report from the appropriate endpoint.
fn poll_hid_mouse_report(
    dev: &crate::drivers::nonos_usb::UsbDevice,
    iface: &crate::drivers::nonos_usb::UsbInterfaceInfo,
) -> Option<Vec<u8>> {
    if let Some(ep) = iface.endpoints.iter().find(|ep| (ep.b_endpoint_address & 0x80) != 0) {
        let mut report = vec![0u8; ep.w_max_packet_size as usize];
        if crate::drivers::nonos_usb::poll_endpoint(
            dev.slot_id,
            ep.b_endpoint_address,
            &mut report,
        ).is_ok() {
            return Some(report);
        }
    }
    None
}

/// USB HID keyboard report and return first non-zero keycode if present.
pub fn parse_keyboard_report(report: &[u8; 8]) -> Option<u8> {
    for &keycode in &report[2..] {
        if keycode != 0 {
            return Some(keycode);
        }
    }
    None
}

/// USB HID mouse report and return (dx, dy, buttons).
pub fn parse_mouse_report(report: &[u8]) -> Option<(i32, i32, Vec<bool>)> {
    if report.len() < 3 { return None; }
    let buttons = (0..3).map(|i| (report[0] & (1 << i)) != 0).collect::<Vec<_>>();
    let dx = report[1] as i8 as i32;
    let dy = report[2] as i8 as i32;
    Some((dx, dy, buttons))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keyboard_report_single_key() {
        let report = [0, 0, 0x04, 0, 0, 0, 0, 0];
        assert_eq!(parse_keyboard_report(&report), Some(0x04));
    }
    #[test]
    fn test_parse_keyboard_report_no_key() {
        let report = [0; 8];
        assert_eq!(parse_keyboard_report(&report), None);
    }
    #[test]
    fn test_parse_keyboard_report_multiple_keys() {
        let report = [0, 0, 0x04, 0x05, 0, 0, 0, 0];
        assert_eq!(parse_keyboard_report(&report), Some(0x04));
    }
    #[test]
    fn test_parse_mouse_report_basic() {
        let report = [0b101, 5, 250];
        let (dx, dy, buttons) = parse_mouse_report(&report).unwrap();
        assert_eq!(dx, 5);
        assert_eq!(dy, -6);
        assert_eq!(buttons, vec![true, false, true]);
    }
    #[test]
    fn test_parse_mouse_report_too_short() {
        let report = [0, 0];
        assert!(parse_mouse_report(&report).is_none());
    }
}
