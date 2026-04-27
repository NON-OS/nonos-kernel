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
use crate::test::framework::TestResult;

pub(crate) fn test_hid_subclass_none() -> TestResult {
    if HID_SUBCLASS_NONE != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_subclass_boot() -> TestResult {
    if HID_SUBCLASS_BOOT != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_protocol_none() -> TestResult {
    if HID_PROTOCOL_NONE != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_protocol_keyboard() -> TestResult {
    if HID_PROTOCOL_KEYBOARD != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_protocol_mouse() -> TestResult {
    if HID_PROTOCOL_MOUSE != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_type_hid() -> TestResult {
    if HID_DT_HID != 0x21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_type_report() -> TestResult {
    if HID_DT_REPORT != 0x22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_descriptor_type_physical() -> TestResult {
    if HID_DT_PHYSICAL != 0x23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_request_get_report() -> TestResult {
    if HID_REQ_GET_REPORT != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_request_get_idle() -> TestResult {
    if HID_REQ_GET_IDLE != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_request_get_protocol() -> TestResult {
    if HID_REQ_GET_PROTOCOL != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_request_set_report() -> TestResult {
    if HID_REQ_SET_REPORT != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_request_set_idle() -> TestResult {
    if HID_REQ_SET_IDLE != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_request_set_protocol() -> TestResult {
    if HID_REQ_SET_PROTOCOL != 0x0B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_report_type_input() -> TestResult {
    if HID_REPORT_TYPE_INPUT != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_report_type_output() -> TestResult {
    if HID_REPORT_TYPE_OUTPUT != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_report_type_feature() -> TestResult {
    if HID_REPORT_TYPE_FEATURE != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_boot_protocol() -> TestResult {
    if HID_BOOT_PROTOCOL != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_report_protocol() -> TestResult {
    if HID_REPORT_PROTOCOL != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_keyboard_report_size() -> TestResult {
    if BOOT_KEYBOARD_REPORT_SIZE != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_mouse_report_size() -> TestResult {
    if BOOT_MOUSE_REPORT_SIZE != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_led_num_lock() -> TestResult {
    if KEYBOARD_LED_NUM_LOCK != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_led_caps_lock() -> TestResult {
    if KEYBOARD_LED_CAPS_LOCK != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_led_scroll_lock() -> TestResult {
    if KEYBOARD_LED_SCROLL_LOCK != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_led_compose() -> TestResult {
    if KEYBOARD_LED_COMPOSE != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_led_kana() -> TestResult {
    if KEYBOARD_LED_KANA != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_left_ctrl() -> TestResult {
    if MOD_LEFT_CTRL != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_left_shift() -> TestResult {
    if MOD_LEFT_SHIFT != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_left_alt() -> TestResult {
    if MOD_LEFT_ALT != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_left_gui() -> TestResult {
    if MOD_LEFT_GUI != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_right_ctrl() -> TestResult {
    if MOD_RIGHT_CTRL != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_right_shift() -> TestResult {
    if MOD_RIGHT_SHIFT != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_right_alt() -> TestResult {
    if MOD_RIGHT_ALT != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_right_gui() -> TestResult {
    if MOD_RIGHT_GUI != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_button_left() -> TestResult {
    if MOUSE_BTN_LEFT != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_button_right() -> TestResult {
    if MOUSE_BTN_RIGHT != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_button_middle() -> TestResult {
    if MOUSE_BTN_MIDDLE != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_hid_devices() -> TestResult {
    if MAX_HID_DEVICES != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hid_poll_interval() -> TestResult {
    if HID_POLL_INTERVAL_MS != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_modifier_bits_unique() -> TestResult {
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
            if modifiers[i] == modifiers[j] {
                return TestResult::Fail;
            }
            if modifiers[i] & modifiers[j] != 0 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_led_bits_unique() -> TestResult {
    let leds = [
        KEYBOARD_LED_NUM_LOCK,
        KEYBOARD_LED_CAPS_LOCK,
        KEYBOARD_LED_SCROLL_LOCK,
        KEYBOARD_LED_COMPOSE,
        KEYBOARD_LED_KANA,
    ];

    for i in 0..leds.len() {
        for j in (i + 1)..leds.len() {
            if leds[i] == leds[j] {
                return TestResult::Fail;
            }
            if leds[i] & leds[j] != 0 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_button_bits_unique() -> TestResult {
    let buttons = [MOUSE_BTN_LEFT, MOUSE_BTN_RIGHT, MOUSE_BTN_MIDDLE];

    for i in 0..buttons.len() {
        for j in (i + 1)..buttons.len() {
            if buttons[i] == buttons[j] {
                return TestResult::Fail;
            }
            if buttons[i] & buttons[j] != 0 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
