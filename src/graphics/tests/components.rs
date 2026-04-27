use crate::graphics::components::input::*;
use crate::test::framework::TestResult;

pub(crate) fn test_input_state_default() -> TestResult {
    let state = InputState::default();
    if state.focused {
        return TestResult::Fail;
    }
    if state.error {
        return TestResult::Fail;
    }
    if state.cursor_pos != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_state_focused() -> TestResult {
    let state = InputState { focused: true, error: false, cursor_pos: 5 };
    if !state.focused {
        return TestResult::Fail;
    }
    if state.error {
        return TestResult::Fail;
    }
    if state.cursor_pos != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_state_error() -> TestResult {
    let state = InputState { focused: false, error: true, cursor_pos: 0 };
    if state.focused {
        return TestResult::Fail;
    }
    if !state.error {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_hit_test_inside() -> TestResult {
    if !input_hit_test(100, 50, 200, 150, 60) {
        return TestResult::Fail;
    }
    if !input_hit_test(100, 50, 200, 100, 50) {
        return TestResult::Fail;
    }
    if !input_hit_test(100, 50, 200, 299, 80) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_hit_test_outside() -> TestResult {
    if input_hit_test(100, 50, 200, 50, 60) {
        return TestResult::Fail;
    }
    if input_hit_test(100, 50, 200, 350, 60) {
        return TestResult::Fail;
    }
    if input_hit_test(100, 50, 200, 150, 30) {
        return TestResult::Fail;
    }
    if input_hit_test(100, 50, 200, 150, 150) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_hit_test_boundary() -> TestResult {
    if !input_hit_test(100, 50, 200, 100, 50) {
        return TestResult::Fail;
    }
    if input_hit_test(100, 50, 200, 99, 50) {
        return TestResult::Fail;
    }
    if input_hit_test(100, 50, 200, 300, 50) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_pos_from_click_start() -> TestResult {
    let pos = cursor_pos_from_click(100, 100, 10);
    if pos != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_pos_from_click_before_text() -> TestResult {
    let pos = cursor_pos_from_click(100, 50, 10);
    if pos != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_pos_from_click_middle() -> TestResult {
    let pos = cursor_pos_from_click(100, 148, 10);
    if !(pos > 0) {
        return TestResult::Fail;
    }
    if !(pos <= 10) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_pos_from_click_past_end() -> TestResult {
    let pos = cursor_pos_from_click(100, 500, 5);
    if pos != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_pos_from_click_exact_char() -> TestResult {
    let base_x = 100;
    let padding = 12;
    let click_x = base_x as i32 + padding as i32 + 8 * 3;
    let pos = cursor_pos_from_click(base_x, click_x, 10);
    if pos != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_pos_zero_length() -> TestResult {
    let pos = cursor_pos_from_click(100, 200, 0);
    if pos != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_state_combinations() -> TestResult {
    let states = [
        InputState { focused: false, error: false, cursor_pos: 0 },
        InputState { focused: true, error: false, cursor_pos: 0 },
        InputState { focused: false, error: true, cursor_pos: 0 },
        InputState { focused: true, error: true, cursor_pos: 5 },
    ];

    for state in states {
        let _ = state.focused;
        let _ = state.error;
        let _ = state.cursor_pos;
    }
    TestResult::Pass
}
