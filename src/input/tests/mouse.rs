// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::input::mouse::{
    is_available, middle_pressed, buttons, take_scroll_delta, scroll_delta, has_scroll_wheel,
};
use crate::input::mouse::state::{
    MOUSE_X, MOUSE_Y, MOUSE_BUTTONS, SCREEN_WIDTH, SCREEN_HEIGHT,
    SCROLL_DELTA, SCROLL_WHEEL_AVAILABLE, MOUSE_AVAILABLE,
    PACKET_INDEX, PACKET_BYTE0, PACKET_BYTE1, PACKET_BYTE2, PACKET_BYTE3,
    set_screen_bounds, position, left_pressed, right_pressed,
};
use core::sync::atomic::Ordering;

fn reset_mouse_state() {
    MOUSE_X.store(400, Ordering::SeqCst);
    MOUSE_Y.store(300, Ordering::SeqCst);
    MOUSE_BUTTONS.store(0, Ordering::SeqCst);
    SCREEN_WIDTH.store(800, Ordering::SeqCst);
    SCREEN_HEIGHT.store(600, Ordering::SeqCst);
    SCROLL_DELTA.store(0, Ordering::SeqCst);
    SCROLL_WHEEL_AVAILABLE.store(false, Ordering::SeqCst);
    MOUSE_AVAILABLE.store(false, Ordering::SeqCst);
    PACKET_INDEX.store(0, Ordering::SeqCst);
    PACKET_BYTE0.store(0, Ordering::SeqCst);
    PACKET_BYTE1.store(0, Ordering::SeqCst);
    PACKET_BYTE2.store(0, Ordering::SeqCst);
    PACKET_BYTE3.store(0, Ordering::SeqCst);
}

#[test]
fn test_mouse_default_position() {
    reset_mouse_state();
    let (x, y) = position();
    assert_eq!(x, 400);
    assert_eq!(y, 300);
}

#[test]
fn test_mouse_set_position() {
    reset_mouse_state();
    MOUSE_X.store(100, Ordering::SeqCst);
    MOUSE_Y.store(200, Ordering::SeqCst);
    let (x, y) = position();
    assert_eq!(x, 100);
    assert_eq!(y, 200);
}

#[test]
fn test_mouse_default_buttons() {
    reset_mouse_state();
    assert_eq!(buttons(), 0);
}

#[test]
fn test_mouse_left_button_not_pressed() {
    reset_mouse_state();
    assert!(!left_pressed());
}

#[test]
fn test_mouse_left_button_pressed() {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x01, Ordering::SeqCst);
    assert!(left_pressed());
}

#[test]
fn test_mouse_right_button_not_pressed() {
    reset_mouse_state();
    assert!(!right_pressed());
}

#[test]
fn test_mouse_right_button_pressed() {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x02, Ordering::SeqCst);
    assert!(right_pressed());
}

#[test]
fn test_mouse_middle_button_not_pressed() {
    reset_mouse_state();
    assert!(!middle_pressed());
}

#[test]
fn test_mouse_middle_button_pressed() {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x04, Ordering::SeqCst);
    assert!(middle_pressed());
}

#[test]
fn test_mouse_all_buttons_pressed() {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x07, Ordering::SeqCst);
    assert!(left_pressed());
    assert!(right_pressed());
    assert!(middle_pressed());
    assert_eq!(buttons(), 0x07);
}

#[test]
fn test_mouse_buttons_bitmask() {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x05, Ordering::SeqCst);
    assert!(left_pressed());
    assert!(!right_pressed());
    assert!(middle_pressed());
}

#[test]
fn test_mouse_set_screen_bounds() {
    reset_mouse_state();
    set_screen_bounds(1920, 1080);
    assert_eq!(SCREEN_WIDTH.load(Ordering::Relaxed), 1920);
    assert_eq!(SCREEN_HEIGHT.load(Ordering::Relaxed), 1080);
    let (x, y) = position();
    assert_eq!(x, 960);
    assert_eq!(y, 540);
}

#[test]
fn test_mouse_screen_bounds_center() {
    reset_mouse_state();
    set_screen_bounds(640, 480);
    let (x, y) = position();
    assert_eq!(x, 320);
    assert_eq!(y, 240);
}

#[test]
fn test_mouse_not_available_by_default() {
    reset_mouse_state();
    assert!(!is_available());
}

#[test]
fn test_mouse_available() {
    reset_mouse_state();
    MOUSE_AVAILABLE.store(true, Ordering::SeqCst);
    assert!(is_available());
}

#[test]
fn test_mouse_scroll_wheel_not_available_by_default() {
    reset_mouse_state();
    assert!(!has_scroll_wheel());
}

#[test]
fn test_mouse_scroll_wheel_available() {
    reset_mouse_state();
    SCROLL_WHEEL_AVAILABLE.store(true, Ordering::SeqCst);
    assert!(has_scroll_wheel());
}

#[test]
fn test_mouse_scroll_delta_zero_default() {
    reset_mouse_state();
    assert_eq!(scroll_delta(), 0);
}

#[test]
fn test_mouse_scroll_delta_positive() {
    reset_mouse_state();
    SCROLL_DELTA.store(3, Ordering::SeqCst);
    assert_eq!(scroll_delta(), 3);
}

#[test]
fn test_mouse_scroll_delta_negative() {
    reset_mouse_state();
    SCROLL_DELTA.store(-3, Ordering::SeqCst);
    assert_eq!(scroll_delta(), -3);
}

#[test]
fn test_mouse_take_scroll_delta_clears() {
    reset_mouse_state();
    SCROLL_DELTA.store(5, Ordering::SeqCst);
    let delta = take_scroll_delta();
    assert_eq!(delta, 5);
    assert_eq!(scroll_delta(), 0);
}

#[test]
fn test_mouse_take_scroll_delta_zero() {
    reset_mouse_state();
    let delta = take_scroll_delta();
    assert_eq!(delta, 0);
}

#[test]
fn test_mouse_take_scroll_delta_multiple() {
    reset_mouse_state();
    SCROLL_DELTA.store(10, Ordering::SeqCst);
    assert_eq!(take_scroll_delta(), 10);
    assert_eq!(take_scroll_delta(), 0);
    assert_eq!(take_scroll_delta(), 0);
}

#[test]
fn test_mouse_packet_index_default() {
    reset_mouse_state();
    assert_eq!(PACKET_INDEX.load(Ordering::Relaxed), 0);
}

#[test]
fn test_mouse_packet_bytes_default() {
    reset_mouse_state();
    assert_eq!(PACKET_BYTE0.load(Ordering::Relaxed), 0);
    assert_eq!(PACKET_BYTE1.load(Ordering::Relaxed), 0);
    assert_eq!(PACKET_BYTE2.load(Ordering::Relaxed), 0);
    assert_eq!(PACKET_BYTE3.load(Ordering::Relaxed), 0);
}

#[test]
fn test_mouse_position_boundary_left() {
    reset_mouse_state();
    MOUSE_X.store(0, Ordering::SeqCst);
    let (x, _) = position();
    assert_eq!(x, 0);
}

#[test]
fn test_mouse_position_boundary_top() {
    reset_mouse_state();
    MOUSE_Y.store(0, Ordering::SeqCst);
    let (_, y) = position();
    assert_eq!(y, 0);
}

#[test]
fn test_mouse_position_negative() {
    reset_mouse_state();
    MOUSE_X.store(-10, Ordering::SeqCst);
    MOUSE_Y.store(-20, Ordering::SeqCst);
    let (x, y) = position();
    assert_eq!(x, -10);
    assert_eq!(y, -20);
}

#[test]
fn test_mouse_large_position() {
    reset_mouse_state();
    MOUSE_X.store(3840, Ordering::SeqCst);
    MOUSE_Y.store(2160, Ordering::SeqCst);
    let (x, y) = position();
    assert_eq!(x, 3840);
    assert_eq!(y, 2160);
}

#[test]
fn test_mouse_screen_bounds_large() {
    reset_mouse_state();
    set_screen_bounds(3840, 2160);
    assert_eq!(SCREEN_WIDTH.load(Ordering::Relaxed), 3840);
    assert_eq!(SCREEN_HEIGHT.load(Ordering::Relaxed), 2160);
}

#[test]
fn test_mouse_screen_bounds_small() {
    reset_mouse_state();
    set_screen_bounds(320, 240);
    assert_eq!(SCREEN_WIDTH.load(Ordering::Relaxed), 320);
    assert_eq!(SCREEN_HEIGHT.load(Ordering::Relaxed), 240);
}

#[test]
fn test_mouse_button_bitmask_values() {
    let left_mask: u8 = 0x01;
    let right_mask: u8 = 0x02;
    let middle_mask: u8 = 0x04;
    assert_eq!(left_mask, 1);
    assert_eq!(right_mask, 2);
    assert_eq!(middle_mask, 4);
}

#[test]
fn test_mouse_atomic_ordering() {
    reset_mouse_state();
    MOUSE_X.store(500, Ordering::Release);
    let x = MOUSE_X.load(Ordering::Acquire);
    assert_eq!(x, 500);
}

#[test]
fn test_mouse_independent_button_states() {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x01, Ordering::SeqCst);
    assert!(left_pressed());
    assert!(!right_pressed());
    assert!(!middle_pressed());

    MOUSE_BUTTONS.store(0x02, Ordering::SeqCst);
    assert!(!left_pressed());
    assert!(right_pressed());
    assert!(!middle_pressed());

    MOUSE_BUTTONS.store(0x04, Ordering::SeqCst);
    assert!(!left_pressed());
    assert!(!right_pressed());
    assert!(middle_pressed());
}
