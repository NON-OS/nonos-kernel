// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::input::mouse::state::{
    left_pressed, position, right_pressed, set_screen_bounds, MOUSE_AVAILABLE, MOUSE_BUTTONS,
    MOUSE_X, MOUSE_Y, PACKET_BYTE0, PACKET_BYTE1, PACKET_BYTE2, PACKET_BYTE3, PACKET_INDEX,
    SCREEN_HEIGHT, SCREEN_WIDTH, SCROLL_DELTA, SCROLL_WHEEL_AVAILABLE,
};
use crate::input::mouse::{
    buttons, has_scroll_wheel, is_available, middle_pressed, scroll_delta, take_scroll_delta,
};
use crate::test::framework::TestResult;
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

pub(crate) fn test_mouse_default_position() -> TestResult {
    reset_mouse_state();
    let (x, y) = position();
    if x != 400 {
        return TestResult::Fail;
    }
    if y != 300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_set_position() -> TestResult {
    reset_mouse_state();
    MOUSE_X.store(100, Ordering::SeqCst);
    MOUSE_Y.store(200, Ordering::SeqCst);
    let (x, y) = position();
    if x != 100 {
        return TestResult::Fail;
    }
    if y != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_default_buttons() -> TestResult {
    reset_mouse_state();
    if buttons() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_left_button_not_pressed() -> TestResult {
    reset_mouse_state();
    if left_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_left_button_pressed() -> TestResult {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x01, Ordering::SeqCst);
    if !left_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_right_button_not_pressed() -> TestResult {
    reset_mouse_state();
    if right_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_right_button_pressed() -> TestResult {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x02, Ordering::SeqCst);
    if !right_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_middle_button_not_pressed() -> TestResult {
    reset_mouse_state();
    if middle_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_middle_button_pressed() -> TestResult {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x04, Ordering::SeqCst);
    if !middle_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_all_buttons_pressed() -> TestResult {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x07, Ordering::SeqCst);
    if !left_pressed() {
        return TestResult::Fail;
    }
    if !right_pressed() {
        return TestResult::Fail;
    }
    if !middle_pressed() {
        return TestResult::Fail;
    }
    if buttons() != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_buttons_bitmask() -> TestResult {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x05, Ordering::SeqCst);
    if !left_pressed() {
        return TestResult::Fail;
    }
    if right_pressed() {
        return TestResult::Fail;
    }
    if !middle_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_set_screen_bounds() -> TestResult {
    reset_mouse_state();
    set_screen_bounds(1920, 1080);
    if SCREEN_WIDTH.load(Ordering::Relaxed) != 1920 {
        return TestResult::Fail;
    }
    if SCREEN_HEIGHT.load(Ordering::Relaxed) != 1080 {
        return TestResult::Fail;
    }
    let (x, y) = position();
    if x != 960 {
        return TestResult::Fail;
    }
    if y != 540 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_screen_bounds_center() -> TestResult {
    reset_mouse_state();
    set_screen_bounds(640, 480);
    let (x, y) = position();
    if x != 320 {
        return TestResult::Fail;
    }
    if y != 240 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_not_available_by_default() -> TestResult {
    reset_mouse_state();
    if is_available() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_available() -> TestResult {
    reset_mouse_state();
    MOUSE_AVAILABLE.store(true, Ordering::SeqCst);
    if !is_available() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_scroll_wheel_not_available_by_default() -> TestResult {
    reset_mouse_state();
    if has_scroll_wheel() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_scroll_wheel_available() -> TestResult {
    reset_mouse_state();
    SCROLL_WHEEL_AVAILABLE.store(true, Ordering::SeqCst);
    if !has_scroll_wheel() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_scroll_delta_zero_default() -> TestResult {
    reset_mouse_state();
    if scroll_delta() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_scroll_delta_positive() -> TestResult {
    reset_mouse_state();
    SCROLL_DELTA.store(3, Ordering::SeqCst);
    if scroll_delta() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_scroll_delta_negative() -> TestResult {
    reset_mouse_state();
    SCROLL_DELTA.store(-3, Ordering::SeqCst);
    if scroll_delta() != -3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_take_scroll_delta_clears() -> TestResult {
    reset_mouse_state();
    SCROLL_DELTA.store(5, Ordering::SeqCst);
    let delta = take_scroll_delta();
    if delta != 5 {
        return TestResult::Fail;
    }
    if scroll_delta() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_take_scroll_delta_zero() -> TestResult {
    reset_mouse_state();
    let delta = take_scroll_delta();
    if delta != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_take_scroll_delta_multiple() -> TestResult {
    reset_mouse_state();
    SCROLL_DELTA.store(10, Ordering::SeqCst);
    if take_scroll_delta() != 10 {
        return TestResult::Fail;
    }
    if take_scroll_delta() != 0 {
        return TestResult::Fail;
    }
    if take_scroll_delta() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_packet_index_default() -> TestResult {
    reset_mouse_state();
    if PACKET_INDEX.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_packet_bytes_default() -> TestResult {
    reset_mouse_state();
    if PACKET_BYTE0.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if PACKET_BYTE1.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if PACKET_BYTE2.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if PACKET_BYTE3.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_position_boundary_left() -> TestResult {
    reset_mouse_state();
    MOUSE_X.store(0, Ordering::SeqCst);
    let (x, _) = position();
    if x != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_position_boundary_top() -> TestResult {
    reset_mouse_state();
    MOUSE_Y.store(0, Ordering::SeqCst);
    let (_, y) = position();
    if y != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_position_negative() -> TestResult {
    reset_mouse_state();
    MOUSE_X.store(-10, Ordering::SeqCst);
    MOUSE_Y.store(-20, Ordering::SeqCst);
    let (x, y) = position();
    if x != -10 {
        return TestResult::Fail;
    }
    if y != -20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_large_position() -> TestResult {
    reset_mouse_state();
    MOUSE_X.store(3840, Ordering::SeqCst);
    MOUSE_Y.store(2160, Ordering::SeqCst);
    let (x, y) = position();
    if x != 3840 {
        return TestResult::Fail;
    }
    if y != 2160 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_screen_bounds_large() -> TestResult {
    reset_mouse_state();
    set_screen_bounds(3840, 2160);
    if SCREEN_WIDTH.load(Ordering::Relaxed) != 3840 {
        return TestResult::Fail;
    }
    if SCREEN_HEIGHT.load(Ordering::Relaxed) != 2160 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_screen_bounds_small() -> TestResult {
    reset_mouse_state();
    set_screen_bounds(320, 240);
    if SCREEN_WIDTH.load(Ordering::Relaxed) != 320 {
        return TestResult::Fail;
    }
    if SCREEN_HEIGHT.load(Ordering::Relaxed) != 240 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_button_bitmask_values() -> TestResult {
    let left_mask: u8 = 0x01;
    let right_mask: u8 = 0x02;
    let middle_mask: u8 = 0x04;
    if left_mask != 1 {
        return TestResult::Fail;
    }
    if right_mask != 2 {
        return TestResult::Fail;
    }
    if middle_mask != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_atomic_ordering() -> TestResult {
    reset_mouse_state();
    MOUSE_X.store(500, Ordering::Release);
    let x = MOUSE_X.load(Ordering::Acquire);
    if x != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_independent_button_states() -> TestResult {
    reset_mouse_state();
    MOUSE_BUTTONS.store(0x01, Ordering::SeqCst);
    if !left_pressed() {
        return TestResult::Fail;
    }
    if right_pressed() {
        return TestResult::Fail;
    }
    if middle_pressed() {
        return TestResult::Fail;
    }

    MOUSE_BUTTONS.store(0x02, Ordering::SeqCst);
    if left_pressed() {
        return TestResult::Fail;
    }
    if !right_pressed() {
        return TestResult::Fail;
    }
    if middle_pressed() {
        return TestResult::Fail;
    }

    MOUSE_BUTTONS.store(0x04, Ordering::SeqCst);
    if left_pressed() {
        return TestResult::Fail;
    }
    if right_pressed() {
        return TestResult::Fail;
    }
    if !middle_pressed() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
