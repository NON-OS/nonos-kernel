// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::input::KeyEvent;

#[test]
fn test_key_event_up_code() {
    assert_eq!(KeyEvent::Up.to_code(), 1);
}

#[test]
fn test_key_event_down_code() {
    assert_eq!(KeyEvent::Down.to_code(), 2);
}

#[test]
fn test_key_event_left_code() {
    assert_eq!(KeyEvent::Left.to_code(), 3);
}

#[test]
fn test_key_event_right_code() {
    assert_eq!(KeyEvent::Right.to_code(), 4);
}

#[test]
fn test_key_event_home_code() {
    assert_eq!(KeyEvent::Home.to_code(), 5);
}

#[test]
fn test_key_event_end_code() {
    assert_eq!(KeyEvent::End.to_code(), 6);
}

#[test]
fn test_key_event_page_up_code() {
    assert_eq!(KeyEvent::PageUp.to_code(), 7);
}

#[test]
fn test_key_event_page_down_code() {
    assert_eq!(KeyEvent::PageDown.to_code(), 8);
}

#[test]
fn test_key_event_insert_code() {
    assert_eq!(KeyEvent::Insert.to_code(), 9);
}

#[test]
fn test_key_event_delete_code() {
    assert_eq!(KeyEvent::Delete.to_code(), 10);
}

#[test]
fn test_key_event_escape_code() {
    assert_eq!(KeyEvent::Escape.to_code(), 11);
}

#[test]
fn test_key_event_backspace_code() {
    assert_eq!(KeyEvent::Backspace.to_code(), 24);
}

#[test]
fn test_key_event_enter_code() {
    assert_eq!(KeyEvent::Enter.to_code(), 25);
}

#[test]
fn test_key_event_f1_to_f12_codes() {
    assert_eq!(KeyEvent::F1.to_code(), 12);
    assert_eq!(KeyEvent::F2.to_code(), 13);
    assert_eq!(KeyEvent::F3.to_code(), 14);
    assert_eq!(KeyEvent::F4.to_code(), 15);
    assert_eq!(KeyEvent::F5.to_code(), 16);
    assert_eq!(KeyEvent::F6.to_code(), 17);
    assert_eq!(KeyEvent::F7.to_code(), 18);
    assert_eq!(KeyEvent::F8.to_code(), 19);
    assert_eq!(KeyEvent::F9.to_code(), 20);
    assert_eq!(KeyEvent::F10.to_code(), 21);
    assert_eq!(KeyEvent::F11.to_code(), 22);
    assert_eq!(KeyEvent::F12.to_code(), 23);
}

#[test]
fn test_key_event_from_code_arrows() {
    assert_eq!(KeyEvent::from_code(1), Some(KeyEvent::Up));
    assert_eq!(KeyEvent::from_code(2), Some(KeyEvent::Down));
    assert_eq!(KeyEvent::from_code(3), Some(KeyEvent::Left));
    assert_eq!(KeyEvent::from_code(4), Some(KeyEvent::Right));
}

#[test]
fn test_key_event_from_code_navigation() {
    assert_eq!(KeyEvent::from_code(5), Some(KeyEvent::Home));
    assert_eq!(KeyEvent::from_code(6), Some(KeyEvent::End));
    assert_eq!(KeyEvent::from_code(7), Some(KeyEvent::PageUp));
    assert_eq!(KeyEvent::from_code(8), Some(KeyEvent::PageDown));
}

#[test]
fn test_key_event_from_code_special() {
    assert_eq!(KeyEvent::from_code(9), Some(KeyEvent::Insert));
    assert_eq!(KeyEvent::from_code(10), Some(KeyEvent::Delete));
    assert_eq!(KeyEvent::from_code(11), Some(KeyEvent::Escape));
    assert_eq!(KeyEvent::from_code(24), Some(KeyEvent::Backspace));
    assert_eq!(KeyEvent::from_code(25), Some(KeyEvent::Enter));
}

#[test]
fn test_key_event_from_code_function_keys() {
    assert_eq!(KeyEvent::from_code(12), Some(KeyEvent::F1));
    assert_eq!(KeyEvent::from_code(13), Some(KeyEvent::F2));
    assert_eq!(KeyEvent::from_code(14), Some(KeyEvent::F3));
    assert_eq!(KeyEvent::from_code(15), Some(KeyEvent::F4));
    assert_eq!(KeyEvent::from_code(16), Some(KeyEvent::F5));
    assert_eq!(KeyEvent::from_code(17), Some(KeyEvent::F6));
    assert_eq!(KeyEvent::from_code(18), Some(KeyEvent::F7));
    assert_eq!(KeyEvent::from_code(19), Some(KeyEvent::F8));
    assert_eq!(KeyEvent::from_code(20), Some(KeyEvent::F9));
    assert_eq!(KeyEvent::from_code(21), Some(KeyEvent::F10));
    assert_eq!(KeyEvent::from_code(22), Some(KeyEvent::F11));
    assert_eq!(KeyEvent::from_code(23), Some(KeyEvent::F12));
}

#[test]
fn test_key_event_from_code_invalid_zero() {
    assert_eq!(KeyEvent::from_code(0), None);
}

#[test]
fn test_key_event_from_code_invalid_high() {
    assert_eq!(KeyEvent::from_code(26), None);
    assert_eq!(KeyEvent::from_code(100), None);
    assert_eq!(KeyEvent::from_code(255), None);
}

#[test]
fn test_key_event_name_arrows() {
    assert_eq!(KeyEvent::Up.name(), "Up");
    assert_eq!(KeyEvent::Down.name(), "Down");
    assert_eq!(KeyEvent::Left.name(), "Left");
    assert_eq!(KeyEvent::Right.name(), "Right");
}

#[test]
fn test_key_event_name_navigation() {
    assert_eq!(KeyEvent::Home.name(), "Home");
    assert_eq!(KeyEvent::End.name(), "End");
    assert_eq!(KeyEvent::PageUp.name(), "PageUp");
    assert_eq!(KeyEvent::PageDown.name(), "PageDown");
}

#[test]
fn test_key_event_name_special() {
    assert_eq!(KeyEvent::Insert.name(), "Insert");
    assert_eq!(KeyEvent::Delete.name(), "Delete");
    assert_eq!(KeyEvent::Escape.name(), "Escape");
    assert_eq!(KeyEvent::Backspace.name(), "Backspace");
    assert_eq!(KeyEvent::Enter.name(), "Enter");
}

#[test]
fn test_key_event_name_function_keys() {
    assert_eq!(KeyEvent::F1.name(), "F1");
    assert_eq!(KeyEvent::F6.name(), "F6");
    assert_eq!(KeyEvent::F12.name(), "F12");
}

#[test]
fn test_key_event_is_arrow_true() {
    assert!(KeyEvent::Up.is_arrow());
    assert!(KeyEvent::Down.is_arrow());
    assert!(KeyEvent::Left.is_arrow());
    assert!(KeyEvent::Right.is_arrow());
}

#[test]
fn test_key_event_is_arrow_false() {
    assert!(!KeyEvent::Home.is_arrow());
    assert!(!KeyEvent::End.is_arrow());
    assert!(!KeyEvent::F1.is_arrow());
    assert!(!KeyEvent::Escape.is_arrow());
    assert!(!KeyEvent::Enter.is_arrow());
}

#[test]
fn test_key_event_is_navigation_true() {
    assert!(KeyEvent::Home.is_navigation());
    assert!(KeyEvent::End.is_navigation());
    assert!(KeyEvent::PageUp.is_navigation());
    assert!(KeyEvent::PageDown.is_navigation());
}

#[test]
fn test_key_event_is_navigation_false() {
    assert!(!KeyEvent::Up.is_navigation());
    assert!(!KeyEvent::F1.is_navigation());
    assert!(!KeyEvent::Escape.is_navigation());
    assert!(!KeyEvent::Insert.is_navigation());
}

#[test]
fn test_key_event_is_function_key_true() {
    assert!(KeyEvent::F1.is_function_key());
    assert!(KeyEvent::F2.is_function_key());
    assert!(KeyEvent::F3.is_function_key());
    assert!(KeyEvent::F4.is_function_key());
    assert!(KeyEvent::F5.is_function_key());
    assert!(KeyEvent::F6.is_function_key());
    assert!(KeyEvent::F7.is_function_key());
    assert!(KeyEvent::F8.is_function_key());
    assert!(KeyEvent::F9.is_function_key());
    assert!(KeyEvent::F10.is_function_key());
    assert!(KeyEvent::F11.is_function_key());
    assert!(KeyEvent::F12.is_function_key());
}

#[test]
fn test_key_event_is_function_key_false() {
    assert!(!KeyEvent::Up.is_function_key());
    assert!(!KeyEvent::Home.is_function_key());
    assert!(!KeyEvent::Escape.is_function_key());
    assert!(!KeyEvent::Enter.is_function_key());
    assert!(!KeyEvent::Delete.is_function_key());
}

#[test]
fn test_key_event_roundtrip_all() {
    let events = [
        KeyEvent::Up, KeyEvent::Down, KeyEvent::Left, KeyEvent::Right,
        KeyEvent::Home, KeyEvent::End, KeyEvent::PageUp, KeyEvent::PageDown,
        KeyEvent::Insert, KeyEvent::Delete, KeyEvent::Escape,
        KeyEvent::Backspace, KeyEvent::Enter,
        KeyEvent::F1, KeyEvent::F2, KeyEvent::F3, KeyEvent::F4,
        KeyEvent::F5, KeyEvent::F6, KeyEvent::F7, KeyEvent::F8,
        KeyEvent::F9, KeyEvent::F10, KeyEvent::F11, KeyEvent::F12,
    ];
    for event in events {
        let code = event.to_code();
        let decoded = KeyEvent::from_code(code);
        assert_eq!(decoded, Some(event));
    }
}

#[test]
fn test_key_event_clone() {
    let event = KeyEvent::Up;
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

#[test]
fn test_key_event_copy() {
    let event = KeyEvent::Down;
    let copied = event;
    assert_eq!(event, copied);
}

#[test]
fn test_key_event_equality() {
    assert_eq!(KeyEvent::Up, KeyEvent::Up);
    assert_ne!(KeyEvent::Up, KeyEvent::Down);
}

#[test]
fn test_key_event_debug() {
    let event = KeyEvent::Enter;
    let debug_str = alloc::format!("{:?}", event);
    assert!(debug_str.contains("Enter"));
}

#[test]
fn test_key_event_unique_codes() {
    let events = [
        KeyEvent::Up, KeyEvent::Down, KeyEvent::Left, KeyEvent::Right,
        KeyEvent::Home, KeyEvent::End, KeyEvent::PageUp, KeyEvent::PageDown,
        KeyEvent::Insert, KeyEvent::Delete, KeyEvent::Escape,
        KeyEvent::Backspace, KeyEvent::Enter,
        KeyEvent::F1, KeyEvent::F2, KeyEvent::F3, KeyEvent::F4,
        KeyEvent::F5, KeyEvent::F6, KeyEvent::F7, KeyEvent::F8,
        KeyEvent::F9, KeyEvent::F10, KeyEvent::F11, KeyEvent::F12,
    ];
    let codes: alloc::vec::Vec<u8> = events.iter().map(|e| e.to_code()).collect();
    for (i, c1) in codes.iter().enumerate() {
        for (j, c2) in codes.iter().enumerate() {
            if i != j {
                assert_ne!(c1, c2);
            }
        }
    }
}

#[test]
fn test_key_event_code_range() {
    let events = [
        KeyEvent::Up, KeyEvent::Down, KeyEvent::Left, KeyEvent::Right,
        KeyEvent::Home, KeyEvent::End, KeyEvent::PageUp, KeyEvent::PageDown,
        KeyEvent::Insert, KeyEvent::Delete, KeyEvent::Escape,
        KeyEvent::Backspace, KeyEvent::Enter,
        KeyEvent::F1, KeyEvent::F2, KeyEvent::F3, KeyEvent::F4,
        KeyEvent::F5, KeyEvent::F6, KeyEvent::F7, KeyEvent::F8,
        KeyEvent::F9, KeyEvent::F10, KeyEvent::F11, KeyEvent::F12,
    ];
    for event in events {
        let code = event.to_code();
        assert!(code >= 1 && code <= 25);
    }
}
