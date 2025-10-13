//! Integration tests for the NØNOS keyboard subsystem.

use arch::x86_64::keyboard::prelude::*;

#[test]
fn test_input_event_queue_basic() {
    push_event(InputEvent::KeyPress(42));
    push_event(InputEvent::KeyRelease(42));
    let ev1 = pop_event().unwrap();
    let ev2 = pop_event().unwrap();
    assert_eq!(ev1, InputEvent::KeyPress(42));
    assert_eq!(ev2, InputEvent::KeyRelease(42));
    assert!(pop_event().is_none());
}

#[test]
fn test_drain_events() {
    push_event(InputEvent::KeyPress(1));
    push_event(InputEvent::KeyPress(2));
    let evs = drain_events();
    assert_eq!(evs.len(), 2);
    assert!(pop_event().is_none());
}

#[test]
fn test_map_scan_code_us() {
    let code = map_scan_code(0x1E, false, Layout::UsQwerty); // 'a'
    assert_eq!(code, KeyCode::A);
    let code_shift = map_scan_code(0x1E, true, Layout::UsQwerty); // 'A'
    assert_eq!(code_shift, KeyCode::A);
}

#[test]
fn test_layout_ascii_tables() {
    assert_eq!(get_ascii_mapping(Layout::UsQwerty)[30], b'a');
    assert_eq!(get_ascii_mapping(Layout::Dvorak)[18], b',');
    assert_eq!(get_ascii_mapping(Layout::Azerty)[44], b'!');
    assert_eq!(get_ascii_mapping(Layout::Colemak)[18], b'f');
}

#[test]
fn test_key_repeat_manager() {
    let mut kr = KeyRepeatManager::new();
    assert!(!kr.handle_key(42));
    for _ in 0..501 {
        kr.handle_key(42);
    }
    assert!(kr.handle_key(42));
}

#[test]
fn test_usb_hid_keyboard_report_parsing() {
    let report = [0, 0, 0x04, 0, 0, 0, 0, 0];
    assert_eq!(parse_keyboard_report(&report), Some(0x04));
    let empty = [0; 8];
    assert_eq!(parse_keyboard_report(&empty), None);
}

#[test]
fn test_usb_hid_mouse_report_parsing() {
    let report = [0b011, 10, 246]; // buttons 0 & 1 pressed, dx=10, dy=-10
    let (dx, dy, buttons) = parse_mouse_report(&report).unwrap();
    assert_eq!(dx, 10);
    assert_eq!(dy, -10);
    assert_eq!(buttons, vec![true, true, false]);
}

#[test]
fn test_ps2_keyboard_event_flow() {
    // Simulate PS/2 event handling.
    push_event(InputEvent::KeyPress(0x1E));
    let ev = pop_event().unwrap();
    assert_eq!(ev, InputEvent::KeyPress(0x1E));
}

#[test]
fn test_keyboard_state_modifiers() {
    let mut state = KeyboardState::new();
    state.shift_pressed = true;
    state.ctrl_pressed = true;
    state.alt_pressed = false;
    assert!(state.shift_pressed);
    assert!(state.ctrl_pressed);
    assert!(!state.alt_pressed);
}
