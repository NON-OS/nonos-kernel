use crate::graphics::components::input::*;

#[test]
fn test_input_state_default() {
    let state = InputState::default();
    assert!(!state.focused);
    assert!(!state.error);
    assert_eq!(state.cursor_pos, 0);
}

#[test]
fn test_input_state_focused() {
    let state = InputState {
        focused: true,
        error: false,
        cursor_pos: 5,
    };
    assert!(state.focused);
    assert!(!state.error);
    assert_eq!(state.cursor_pos, 5);
}

#[test]
fn test_input_state_error() {
    let state = InputState {
        focused: false,
        error: true,
        cursor_pos: 0,
    };
    assert!(!state.focused);
    assert!(state.error);
}

#[test]
fn test_input_hit_test_inside() {
    assert!(input_hit_test(100, 50, 200, 150, 60));
    assert!(input_hit_test(100, 50, 200, 100, 50));
    assert!(input_hit_test(100, 50, 200, 299, 80));
}

#[test]
fn test_input_hit_test_outside() {
    assert!(!input_hit_test(100, 50, 200, 50, 60));
    assert!(!input_hit_test(100, 50, 200, 350, 60));
    assert!(!input_hit_test(100, 50, 200, 150, 30));
    assert!(!input_hit_test(100, 50, 200, 150, 150));
}

#[test]
fn test_input_hit_test_boundary() {
    assert!(input_hit_test(100, 50, 200, 100, 50));
    assert!(!input_hit_test(100, 50, 200, 99, 50));
    assert!(!input_hit_test(100, 50, 200, 300, 50));
}

#[test]
fn test_cursor_pos_from_click_start() {
    let pos = cursor_pos_from_click(100, 100, 10);
    assert_eq!(pos, 0);
}

#[test]
fn test_cursor_pos_from_click_before_text() {
    let pos = cursor_pos_from_click(100, 50, 10);
    assert_eq!(pos, 0);
}

#[test]
fn test_cursor_pos_from_click_middle() {
    let pos = cursor_pos_from_click(100, 148, 10);
    assert!(pos > 0);
    assert!(pos <= 10);
}

#[test]
fn test_cursor_pos_from_click_past_end() {
    let pos = cursor_pos_from_click(100, 500, 5);
    assert_eq!(pos, 5);
}

#[test]
fn test_cursor_pos_from_click_exact_char() {
    let base_x = 100;
    let padding = 12;
    let click_x = base_x as i32 + padding as i32 + 8 * 3;
    let pos = cursor_pos_from_click(base_x, click_x, 10);
    assert_eq!(pos, 3);
}

#[test]
fn test_cursor_pos_zero_length() {
    let pos = cursor_pos_from_click(100, 200, 0);
    assert_eq!(pos, 0);
}

#[test]
fn test_input_state_combinations() {
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
}
