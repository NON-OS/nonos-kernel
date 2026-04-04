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

use crate::drivers::usb::hid::*;

#[test]
fn test_hid_subclass_none() {
    assert_eq!(HID_SUBCLASS_NONE, 0x00);
}

#[test]
fn test_hid_subclass_boot() {
    assert_eq!(HID_SUBCLASS_BOOT, 0x01);
}

#[test]
fn test_hid_protocol_none() {
    assert_eq!(HID_PROTOCOL_NONE, 0x00);
}

#[test]
fn test_hid_protocol_keyboard() {
    assert_eq!(HID_PROTOCOL_KEYBOARD, 0x01);
}

#[test]
fn test_hid_protocol_mouse() {
    assert_eq!(HID_PROTOCOL_MOUSE, 0x02);
}

#[test]
fn test_hid_descriptor_type_hid() {
    assert_eq!(HID_DT_HID, 0x21);
}

#[test]
fn test_hid_descriptor_type_report() {
    assert_eq!(HID_DT_REPORT, 0x22);
}

#[test]
fn test_hid_descriptor_type_physical() {
    assert_eq!(HID_DT_PHYSICAL, 0x23);
}

#[test]
fn test_hid_request_get_report() {
    assert_eq!(HID_REQ_GET_REPORT, 0x01);
}

#[test]
fn test_hid_request_get_idle() {
    assert_eq!(HID_REQ_GET_IDLE, 0x02);
}

#[test]
fn test_hid_request_get_protocol() {
    assert_eq!(HID_REQ_GET_PROTOCOL, 0x03);
}

#[test]
fn test_hid_request_set_report() {
    assert_eq!(HID_REQ_SET_REPORT, 0x09);
}

#[test]
fn test_hid_request_set_idle() {
    assert_eq!(HID_REQ_SET_IDLE, 0x0A);
}

#[test]
fn test_hid_request_set_protocol() {
    assert_eq!(HID_REQ_SET_PROTOCOL, 0x0B);
}

#[test]
fn test_hid_report_type_input() {
    assert_eq!(HID_REPORT_TYPE_INPUT, 0x01);
}

#[test]
fn test_hid_report_type_output() {
    assert_eq!(HID_REPORT_TYPE_OUTPUT, 0x02);
}

#[test]
fn test_hid_report_type_feature() {
    assert_eq!(HID_REPORT_TYPE_FEATURE, 0x03);
}

#[test]
fn test_hid_boot_protocol() {
    assert_eq!(HID_BOOT_PROTOCOL, 0x00);
}

#[test]
fn test_hid_report_protocol() {
    assert_eq!(HID_REPORT_PROTOCOL, 0x01);
}

#[test]
fn test_boot_keyboard_report_size() {
    assert_eq!(BOOT_KEYBOARD_REPORT_SIZE, 8);
}

#[test]
fn test_boot_mouse_report_size() {
    assert_eq!(BOOT_MOUSE_REPORT_SIZE, 3);
}

#[test]
fn test_keyboard_led_num_lock() {
    assert_eq!(KEYBOARD_LED_NUM_LOCK, 0x01);
}

#[test]
fn test_keyboard_led_caps_lock() {
    assert_eq!(KEYBOARD_LED_CAPS_LOCK, 0x02);
}

#[test]
fn test_keyboard_led_scroll_lock() {
    assert_eq!(KEYBOARD_LED_SCROLL_LOCK, 0x04);
}

#[test]
fn test_keyboard_led_compose() {
    assert_eq!(KEYBOARD_LED_COMPOSE, 0x08);
}

#[test]
fn test_keyboard_led_kana() {
    assert_eq!(KEYBOARD_LED_KANA, 0x10);
}

#[test]
fn test_modifier_left_ctrl() {
    assert_eq!(MOD_LEFT_CTRL, 0x01);
}

#[test]
fn test_modifier_left_shift() {
    assert_eq!(MOD_LEFT_SHIFT, 0x02);
}

#[test]
fn test_modifier_left_alt() {
    assert_eq!(MOD_LEFT_ALT, 0x04);
}

#[test]
fn test_modifier_left_gui() {
    assert_eq!(MOD_LEFT_GUI, 0x08);
}

#[test]
fn test_modifier_right_ctrl() {
    assert_eq!(MOD_RIGHT_CTRL, 0x10);
}

#[test]
fn test_modifier_right_shift() {
    assert_eq!(MOD_RIGHT_SHIFT, 0x20);
}

#[test]
fn test_modifier_right_alt() {
    assert_eq!(MOD_RIGHT_ALT, 0x40);
}

#[test]
fn test_modifier_right_gui() {
    assert_eq!(MOD_RIGHT_GUI, 0x80);
}

#[test]
fn test_mouse_button_left() {
    assert_eq!(MOUSE_BTN_LEFT, 0x01);
}

#[test]
fn test_mouse_button_right() {
    assert_eq!(MOUSE_BTN_RIGHT, 0x02);
}

#[test]
fn test_mouse_button_middle() {
    assert_eq!(MOUSE_BTN_MIDDLE, 0x04);
}

#[test]
fn test_max_hid_devices() {
    assert_eq!(MAX_HID_DEVICES, 8);
}

#[test]
fn test_hid_poll_interval() {
    assert_eq!(HID_POLL_INTERVAL_MS, 10);
}

#[test]
fn test_modifier_bits_unique() {
    let modifiers = [
        MOD_LEFT_CTRL,
        MOD_LEFT_SHIFT,
        MOD_LEFT_ALT,
        MOD_LEFT_GUI,
        MOD_RIGHT_CTRL,
        MOD_RIGHT_SHIFT,
        MOD_RIGHT_ALT,
        MOD_RIGHT_GUI,
    ];

    for i in 0..modifiers.len() {
        for j in (i + 1)..modifiers.len() {
            assert_ne!(modifiers[i], modifiers[j]);
            assert_eq!(modifiers[i] & modifiers[j], 0);
        }
    }
}

#[test]
fn test_led_bits_unique() {
    let leds = [
        KEYBOARD_LED_NUM_LOCK,
        KEYBOARD_LED_CAPS_LOCK,
        KEYBOARD_LED_SCROLL_LOCK,
        KEYBOARD_LED_COMPOSE,
        KEYBOARD_LED_KANA,
    ];

    for i in 0..leds.len() {
        for j in (i + 1)..leds.len() {
            assert_ne!(leds[i], leds[j]);
            assert_eq!(leds[i] & leds[j], 0);
        }
    }
}

#[test]
fn test_mouse_button_bits_unique() {
    let buttons = [MOUSE_BTN_LEFT, MOUSE_BTN_RIGHT, MOUSE_BTN_MIDDLE];

    for i in 0..buttons.len() {
        for j in (i + 1)..buttons.len() {
            assert_ne!(buttons[i], buttons[j]);
            assert_eq!(buttons[i] & buttons[j], 0);
        }
    }
}
