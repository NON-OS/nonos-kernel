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

use super::*;

#[test]
fn test_scancode_table_coverage() {
    assert!(NORMAL[0x10].is_some());
    assert!(NORMAL[0x1E].is_some());
    assert!(NORMAL[0x2C].is_some());
    assert!(NORMAL[0x39].is_some());

    assert!(SHIFTED[0x10].is_some());
    assert!(SHIFTED[0x1E].is_some());
}

#[test]
fn test_scancode_values() {
    assert_eq!(NORMAL[0x10], Some(b'q'));
    assert_eq!(NORMAL[0x11], Some(b'w'));
    assert_eq!(NORMAL[0x12], Some(b'e'));
    assert_eq!(NORMAL[0x1C], Some(b'\n'));

    assert_eq!(SHIFTED[0x10], Some(b'Q'));
    assert_eq!(SHIFTED[0x02], Some(b'!'));
    assert_eq!(SHIFTED[0x03], Some(b'@'));
}

#[test]
fn test_key_event_codes() {
    assert_eq!(KeyEvent::Up.to_code(), 1);
    assert_eq!(KeyEvent::Down.to_code(), 2);
    assert_eq!(KeyEvent::Left.to_code(), 3);
    assert_eq!(KeyEvent::Right.to_code(), 4);

    assert_eq!(KeyEvent::from_code(1), Some(KeyEvent::Up));
    assert_eq!(KeyEvent::from_code(2), Some(KeyEvent::Down));
    assert_eq!(KeyEvent::from_code(0), None);
}

#[test]
fn test_key_event_properties() {
    assert!(KeyEvent::Up.is_arrow());
    assert!(KeyEvent::Down.is_arrow());
    assert!(KeyEvent::Left.is_arrow());
    assert!(KeyEvent::Right.is_arrow());
    assert!(!KeyEvent::Home.is_arrow());

    assert!(KeyEvent::Home.is_navigation());
    assert!(KeyEvent::End.is_navigation());
    assert!(KeyEvent::PageUp.is_navigation());
    assert!(KeyEvent::PageDown.is_navigation());
    assert!(!KeyEvent::Up.is_navigation());

    assert!(KeyEvent::F1.is_function_key());
    assert!(KeyEvent::F12.is_function_key());
    assert!(!KeyEvent::Up.is_function_key());
}

#[test]
fn test_ring_buffer_empty() {
    let ring: SpscU8Ring<16> = SpscU8Ring::new();
    assert!(ring.is_empty());
    assert_eq!(ring.pop(), None);
}

#[test]
fn test_ring_buffer_push_pop() {
    let mut ring: SpscU8Ring<16> = SpscU8Ring::new();
    ring.push(b'h');
    ring.push(b'e');
    ring.push(b'l');
    ring.push(b'l');
    ring.push(b'o');

    assert!(!ring.is_empty());
    assert_eq!(ring.pop(), Some(b'h'));
    assert_eq!(ring.pop(), Some(b'e'));
    assert_eq!(ring.pop(), Some(b'l'));
    assert_eq!(ring.pop(), Some(b'l'));
    assert_eq!(ring.pop(), Some(b'o'));
    assert!(ring.is_empty());
}

#[test]
fn test_event_ring_buffer() {
    let mut ring: SpscEvtRing<8> = SpscEvtRing::new();
    ring.push_evt(KeyEvent::Up);
    ring.push_evt(KeyEvent::Down);
    ring.push_evt(KeyEvent::Left);
    ring.push_evt(KeyEvent::Right);

    assert_eq!(ring.pop_evt(), Some(KeyEvent::Up));
    assert_eq!(ring.pop_evt(), Some(KeyEvent::Down));
    assert_eq!(ring.pop_evt(), Some(KeyEvent::Left));
    assert_eq!(ring.pop_evt(), Some(KeyEvent::Right));
    assert_eq!(ring.pop_evt(), None);
}

#[test]
fn test_constants() {
    assert_eq!(KBD_DATA, 0x60);
    assert_eq!(KBD_STATUS, 0x64);

    assert_eq!(KBD_VECTOR, 0x21);

    assert_eq!(SC_BREAK_BIT, 0x80);

    assert_eq!(SC_EXT_E0, 0xE0);
}

#[test]
fn test_modifier_scancodes() {
    assert_eq!(SC_LSHIFT, 0x2A);
    assert_eq!(SC_RSHIFT, 0x36);
    assert_eq!(SC_LCTRL, 0x1D);
    assert_eq!(SC_LALT, 0x38);
    assert_eq!(SC_CAPSLOCK, 0x3A);
}

#[test]
fn test_led_bits() {
    assert_eq!(LED_SCROLL_LOCK, 0b001);
    assert_eq!(LED_NUM_LOCK, 0b010);
    assert_eq!(LED_CAPS_LOCK, 0b100);
}

#[test]
fn test_ring_sizes() {
    assert_eq!(CHAR_RING_SIZE, 1024);
    assert_eq!(EVT_RING_SIZE, 64);
    assert!(CHAR_RING_SIZE.is_power_of_two());
    assert!(EVT_RING_SIZE.is_power_of_two());
}

#[test]
fn test_keyboard_interface() {
    let kbd = get_keyboard();
    let _ = kbd.has_data();
    let _ = kbd.has_event();
    let _ = kbd.get_modifiers();
}
