// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::input::KeyEvent;
use crate::test::framework::TestResult;

pub(crate) fn test_key_event_up_code() -> TestResult {
    if KeyEvent::Up.to_code() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_down_code() -> TestResult {
    if KeyEvent::Down.to_code() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_left_code() -> TestResult {
    if KeyEvent::Left.to_code() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_right_code() -> TestResult {
    if KeyEvent::Right.to_code() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_home_code() -> TestResult {
    if KeyEvent::Home.to_code() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_end_code() -> TestResult {
    if KeyEvent::End.to_code() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_page_up_code() -> TestResult {
    if KeyEvent::PageUp.to_code() != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_page_down_code() -> TestResult {
    if KeyEvent::PageDown.to_code() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_insert_code() -> TestResult {
    if KeyEvent::Insert.to_code() != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_delete_code() -> TestResult {
    if KeyEvent::Delete.to_code() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_escape_code() -> TestResult {
    if KeyEvent::Escape.to_code() != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_backspace_code() -> TestResult {
    if KeyEvent::Backspace.to_code() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_enter_code() -> TestResult {
    if KeyEvent::Enter.to_code() != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_f1_to_f12_codes() -> TestResult {
    if KeyEvent::F1.to_code() != 12 {
        return TestResult::Fail;
    }
    if KeyEvent::F2.to_code() != 13 {
        return TestResult::Fail;
    }
    if KeyEvent::F3.to_code() != 14 {
        return TestResult::Fail;
    }
    if KeyEvent::F4.to_code() != 15 {
        return TestResult::Fail;
    }
    if KeyEvent::F5.to_code() != 16 {
        return TestResult::Fail;
    }
    if KeyEvent::F6.to_code() != 17 {
        return TestResult::Fail;
    }
    if KeyEvent::F7.to_code() != 18 {
        return TestResult::Fail;
    }
    if KeyEvent::F8.to_code() != 19 {
        return TestResult::Fail;
    }
    if KeyEvent::F9.to_code() != 20 {
        return TestResult::Fail;
    }
    if KeyEvent::F10.to_code() != 21 {
        return TestResult::Fail;
    }
    if KeyEvent::F11.to_code() != 22 {
        return TestResult::Fail;
    }
    if KeyEvent::F12.to_code() != 23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_from_code_arrows() -> TestResult {
    if KeyEvent::from_code(1) != Some(KeyEvent::Up) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(2) != Some(KeyEvent::Down) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(3) != Some(KeyEvent::Left) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(4) != Some(KeyEvent::Right) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_from_code_navigation() -> TestResult {
    if KeyEvent::from_code(5) != Some(KeyEvent::Home) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(6) != Some(KeyEvent::End) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(7) != Some(KeyEvent::PageUp) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(8) != Some(KeyEvent::PageDown) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_from_code_special() -> TestResult {
    if KeyEvent::from_code(9) != Some(KeyEvent::Insert) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(10) != Some(KeyEvent::Delete) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(11) != Some(KeyEvent::Escape) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(24) != Some(KeyEvent::Backspace) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(25) != Some(KeyEvent::Enter) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_from_code_function_keys() -> TestResult {
    if KeyEvent::from_code(12) != Some(KeyEvent::F1) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(13) != Some(KeyEvent::F2) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(14) != Some(KeyEvent::F3) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(15) != Some(KeyEvent::F4) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(16) != Some(KeyEvent::F5) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(17) != Some(KeyEvent::F6) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(18) != Some(KeyEvent::F7) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(19) != Some(KeyEvent::F8) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(20) != Some(KeyEvent::F9) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(21) != Some(KeyEvent::F10) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(22) != Some(KeyEvent::F11) {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(23) != Some(KeyEvent::F12) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_from_code_invalid_zero() -> TestResult {
    if KeyEvent::from_code(0) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_from_code_invalid_high() -> TestResult {
    if KeyEvent::from_code(26) != None {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(100) != None {
        return TestResult::Fail;
    }
    if KeyEvent::from_code(255) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_name_arrows() -> TestResult {
    if KeyEvent::Up.name() != "Up" {
        return TestResult::Fail;
    }
    if KeyEvent::Down.name() != "Down" {
        return TestResult::Fail;
    }
    if KeyEvent::Left.name() != "Left" {
        return TestResult::Fail;
    }
    if KeyEvent::Right.name() != "Right" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_name_navigation() -> TestResult {
    if KeyEvent::Home.name() != "Home" {
        return TestResult::Fail;
    }
    if KeyEvent::End.name() != "End" {
        return TestResult::Fail;
    }
    if KeyEvent::PageUp.name() != "PageUp" {
        return TestResult::Fail;
    }
    if KeyEvent::PageDown.name() != "PageDown" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_name_special() -> TestResult {
    if KeyEvent::Insert.name() != "Insert" {
        return TestResult::Fail;
    }
    if KeyEvent::Delete.name() != "Delete" {
        return TestResult::Fail;
    }
    if KeyEvent::Escape.name() != "Escape" {
        return TestResult::Fail;
    }
    if KeyEvent::Backspace.name() != "Backspace" {
        return TestResult::Fail;
    }
    if KeyEvent::Enter.name() != "Enter" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_name_function_keys() -> TestResult {
    if KeyEvent::F1.name() != "F1" {
        return TestResult::Fail;
    }
    if KeyEvent::F6.name() != "F6" {
        return TestResult::Fail;
    }
    if KeyEvent::F12.name() != "F12" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_is_arrow_true() -> TestResult {
    if !KeyEvent::Up.is_arrow() {
        return TestResult::Fail;
    }
    if !KeyEvent::Down.is_arrow() {
        return TestResult::Fail;
    }
    if !KeyEvent::Left.is_arrow() {
        return TestResult::Fail;
    }
    if !KeyEvent::Right.is_arrow() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_is_arrow_false() -> TestResult {
    if KeyEvent::Home.is_arrow() {
        return TestResult::Fail;
    }
    if KeyEvent::End.is_arrow() {
        return TestResult::Fail;
    }
    if KeyEvent::F1.is_arrow() {
        return TestResult::Fail;
    }
    if KeyEvent::Escape.is_arrow() {
        return TestResult::Fail;
    }
    if KeyEvent::Enter.is_arrow() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_is_navigation_true() -> TestResult {
    if !KeyEvent::Home.is_navigation() {
        return TestResult::Fail;
    }
    if !KeyEvent::End.is_navigation() {
        return TestResult::Fail;
    }
    if !KeyEvent::PageUp.is_navigation() {
        return TestResult::Fail;
    }
    if !KeyEvent::PageDown.is_navigation() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_is_navigation_false() -> TestResult {
    if KeyEvent::Up.is_navigation() {
        return TestResult::Fail;
    }
    if KeyEvent::F1.is_navigation() {
        return TestResult::Fail;
    }
    if KeyEvent::Escape.is_navigation() {
        return TestResult::Fail;
    }
    if KeyEvent::Insert.is_navigation() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_is_function_key_true() -> TestResult {
    if !KeyEvent::F1.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F2.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F3.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F4.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F5.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F6.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F7.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F8.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F9.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F10.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F11.is_function_key() {
        return TestResult::Fail;
    }
    if !KeyEvent::F12.is_function_key() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_is_function_key_false() -> TestResult {
    if KeyEvent::Up.is_function_key() {
        return TestResult::Fail;
    }
    if KeyEvent::Home.is_function_key() {
        return TestResult::Fail;
    }
    if KeyEvent::Escape.is_function_key() {
        return TestResult::Fail;
    }
    if KeyEvent::Enter.is_function_key() {
        return TestResult::Fail;
    }
    if KeyEvent::Delete.is_function_key() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_roundtrip_all() -> TestResult {
    let events = [
        KeyEvent::Up,
        KeyEvent::Down,
        KeyEvent::Left,
        KeyEvent::Right,
        KeyEvent::Home,
        KeyEvent::End,
        KeyEvent::PageUp,
        KeyEvent::PageDown,
        KeyEvent::Insert,
        KeyEvent::Delete,
        KeyEvent::Escape,
        KeyEvent::Backspace,
        KeyEvent::Enter,
        KeyEvent::F1,
        KeyEvent::F2,
        KeyEvent::F3,
        KeyEvent::F4,
        KeyEvent::F5,
        KeyEvent::F6,
        KeyEvent::F7,
        KeyEvent::F8,
        KeyEvent::F9,
        KeyEvent::F10,
        KeyEvent::F11,
        KeyEvent::F12,
    ];
    for event in events {
        let code = event.to_code();
        let decoded = KeyEvent::from_code(code);
        if decoded != Some(event) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_clone() -> TestResult {
    let event = KeyEvent::Up;
    let cloned = event.clone();
    if event != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_copy() -> TestResult {
    let event = KeyEvent::Down;
    let copied = event;
    if event != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_equality() -> TestResult {
    if KeyEvent::Up != KeyEvent::Up {
        return TestResult::Fail;
    }
    if KeyEvent::Up == KeyEvent::Down {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_debug() -> TestResult {
    let event = KeyEvent::Enter;
    let debug_str = alloc::format!("{:?}", event);
    if !debug_str.contains("Enter") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_unique_codes() -> TestResult {
    let events = [
        KeyEvent::Up,
        KeyEvent::Down,
        KeyEvent::Left,
        KeyEvent::Right,
        KeyEvent::Home,
        KeyEvent::End,
        KeyEvent::PageUp,
        KeyEvent::PageDown,
        KeyEvent::Insert,
        KeyEvent::Delete,
        KeyEvent::Escape,
        KeyEvent::Backspace,
        KeyEvent::Enter,
        KeyEvent::F1,
        KeyEvent::F2,
        KeyEvent::F3,
        KeyEvent::F4,
        KeyEvent::F5,
        KeyEvent::F6,
        KeyEvent::F7,
        KeyEvent::F8,
        KeyEvent::F9,
        KeyEvent::F10,
        KeyEvent::F11,
        KeyEvent::F12,
    ];
    let codes: alloc::vec::Vec<u8> = events.iter().map(|e| e.to_code()).collect();
    for (i, c1) in codes.iter().enumerate() {
        for (j, c2) in codes.iter().enumerate() {
            if i != j {
                if c1 == c2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_key_event_code_range() -> TestResult {
    let events = [
        KeyEvent::Up,
        KeyEvent::Down,
        KeyEvent::Left,
        KeyEvent::Right,
        KeyEvent::Home,
        KeyEvent::End,
        KeyEvent::PageUp,
        KeyEvent::PageDown,
        KeyEvent::Insert,
        KeyEvent::Delete,
        KeyEvent::Escape,
        KeyEvent::Backspace,
        KeyEvent::Enter,
        KeyEvent::F1,
        KeyEvent::F2,
        KeyEvent::F3,
        KeyEvent::F4,
        KeyEvent::F5,
        KeyEvent::F6,
        KeyEvent::F7,
        KeyEvent::F8,
        KeyEvent::F9,
        KeyEvent::F10,
        KeyEvent::F11,
        KeyEvent::F12,
    ];
    for event in events {
        let code = event.to_code();
        if !(code >= 1 && code <= 25) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
