use crate::input::i2c_hid::touchpad::constants::{
    DOUBLE_TAP_TIMEOUT_US, MAX_CONTACTS, PALM_EDGE_THRESHOLD, PALM_MIN_AREA, PALM_MIN_PRESSURE,
    PINCH_THRESHOLD, SCROLL_THRESHOLD, SWIPE_THRESHOLD, TAP_TIMEOUT_US,
};
use crate::input::i2c_hid::touchpad::gesture::{
    detect_four_finger_gesture, detect_three_finger_gesture, detect_two_finger_gesture,
    is_double_tap, is_tap_event, tap_timing_config,
};
use crate::input::i2c_hid::touchpad::types::{Gesture, TouchPoint, TouchpadState, TrackedContact};
use crate::input::i2c_hid::touchpad::util::{apply_acceleration, distance, isqrt};
use crate::test::framework::TestResult;

pub(crate) fn test_touch_point_default() -> TestResult {
    let point = TouchPoint::default();
    if point.id != 0 {
        return TestResult::Fail;
    }
    if point.x != 0 {
        return TestResult::Fail;
    }
    if point.y != 0 {
        return TestResult::Fail;
    }
    if point.tip {
        return TestResult::Fail;
    }
    if point.pressure != 0 {
        return TestResult::Fail;
    }
    if point.width != 0 {
        return TestResult::Fail;
    }
    if point.height != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_area() -> TestResult {
    let point =
        TouchPoint { id: 1, x: 100, y: 200, tip: true, pressure: 50, width: 10, height: 20 };
    if point.area() != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_area_zero() -> TestResult {
    let point = TouchPoint::default();
    if point.area() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_is_palm_by_area() -> TestResult {
    let point =
        TouchPoint { id: 1, x: 500, y: 500, tip: true, pressure: 50, width: 25, height: 20 };
    if !point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_is_palm_by_pressure() -> TestResult {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: 500,
        tip: true,
        pressure: PALM_MIN_PRESSURE + 1,
        width: 5,
        height: 5,
    };
    if !point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_is_palm_by_left_edge() -> TestResult {
    let point = TouchPoint {
        id: 1,
        x: PALM_EDGE_THRESHOLD - 1,
        y: 500,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    if !point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_is_palm_by_right_edge() -> TestResult {
    let point = TouchPoint {
        id: 1,
        x: 1000 - PALM_EDGE_THRESHOLD + 1,
        y: 500,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    if !point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_is_palm_by_top_edge() -> TestResult {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: PALM_EDGE_THRESHOLD - 1,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    if !point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_is_palm_by_bottom_edge() -> TestResult {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: 1000 - PALM_EDGE_THRESHOLD + 1,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    if !point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_not_palm() -> TestResult {
    let point = TouchPoint { id: 1, x: 500, y: 500, tip: true, pressure: 50, width: 5, height: 5 };
    if point.is_palm_candidate(1000, 1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_default() -> TestResult {
    let gesture = Gesture::default();
    if gesture != Gesture::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_variants() -> TestResult {
    if Gesture::None != Gesture::None {
        return TestResult::Fail;
    }
    if Gesture::Tap != Gesture::Tap {
        return TestResult::Fail;
    }
    if Gesture::DoubleTap != Gesture::DoubleTap {
        return TestResult::Fail;
    }
    if Gesture::TwoFingerTap != Gesture::TwoFingerTap {
        return TestResult::Fail;
    }
    if Gesture::ThreeFingerTap != Gesture::ThreeFingerTap {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_two_finger_scroll() -> TestResult {
    let gesture = Gesture::TwoFingerScroll { dx: 10, dy: 20 };
    match gesture {
        Gesture::TwoFingerScroll { dx, dy } => {
            if dx != 10 {
                return TestResult::Fail;
            }
            if dy != 20 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_pinch_zoom() -> TestResult {
    let gesture = Gesture::PinchZoom { scale: 50 };
    match gesture {
        Gesture::PinchZoom { scale } => {
            if scale != 50 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_three_finger_swipes() -> TestResult {
    if Gesture::ThreeFingerSwipeLeft != Gesture::ThreeFingerSwipeLeft {
        return TestResult::Fail;
    }
    if Gesture::ThreeFingerSwipeRight != Gesture::ThreeFingerSwipeRight {
        return TestResult::Fail;
    }
    if Gesture::ThreeFingerSwipeUp != Gesture::ThreeFingerSwipeUp {
        return TestResult::Fail;
    }
    if Gesture::ThreeFingerSwipeDown != Gesture::ThreeFingerSwipeDown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_four_finger_swipes() -> TestResult {
    if Gesture::FourFingerSwipeUp != Gesture::FourFingerSwipeUp {
        return TestResult::Fail;
    }
    if Gesture::FourFingerSwipeDown != Gesture::FourFingerSwipeDown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_state_default() -> TestResult {
    let state = TouchpadState::default();
    if state.delta_x != 0 {
        return TestResult::Fail;
    }
    if state.delta_y != 0 {
        return TestResult::Fail;
    }
    if state.buttons != 0 {
        return TestResult::Fail;
    }
    if state.contact_count != 0 {
        return TestResult::Fail;
    }
    if state.gesture != Gesture::None {
        return TestResult::Fail;
    }
    if state.scroll_x != 0 {
        return TestResult::Fail;
    }
    if state.scroll_y != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tracked_contact_default() -> TestResult {
    let contact = TrackedContact::default();
    if contact.id != 0 {
        return TestResult::Fail;
    }
    if contact.start_x != 0 {
        return TestResult::Fail;
    }
    if contact.start_y != 0 {
        return TestResult::Fail;
    }
    if contact.current_x != 0 {
        return TestResult::Fail;
    }
    if contact.current_y != 0 {
        return TestResult::Fail;
    }
    if contact.active {
        return TestResult::Fail;
    }
    if contact.is_palm {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constants_max_contacts() -> TestResult {
    if MAX_CONTACTS != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constants_palm_detection() -> TestResult {
    if PALM_MIN_PRESSURE != 200 {
        return TestResult::Fail;
    }
    if PALM_MIN_AREA != 400 {
        return TestResult::Fail;
    }
    if PALM_EDGE_THRESHOLD != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constants_tap_timeouts() -> TestResult {
    if TAP_TIMEOUT_US != 200_000 {
        return TestResult::Fail;
    }
    if DOUBLE_TAP_TIMEOUT_US != 400_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_constants_gesture_thresholds() -> TestResult {
    if SCROLL_THRESHOLD != 10 {
        return TestResult::Fail;
    }
    if PINCH_THRESHOLD != 20 {
        return TestResult::Fail;
    }
    if SWIPE_THRESHOLD != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tap_event_short() -> TestResult {
    if !is_tap_event(0, TAP_TIMEOUT_US - 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tap_event_too_long() -> TestResult {
    if is_tap_event(0, TAP_TIMEOUT_US + 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_double_tap_quick() -> TestResult {
    if !is_double_tap(0, DOUBLE_TAP_TIMEOUT_US - 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_double_tap_too_slow() -> TestResult {
    if is_double_tap(0, DOUBLE_TAP_TIMEOUT_US + 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tap_timing_config() -> TestResult {
    let (tap, double_tap) = tap_timing_config();
    if tap != TAP_TIMEOUT_US {
        return TestResult::Fail;
    }
    if double_tap != DOUBLE_TAP_TIMEOUT_US {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_detect_two_finger_gesture_no_contacts() -> TestResult {
    let tracked = [];
    let mut state = TouchpadState::default();
    let mut gesture_active = false;
    let mut two_finger_start_distance = 0;
    let mut tap_moved = false;

    let result = detect_two_finger_gesture(
        &tracked,
        &mut state,
        &mut gesture_active,
        &mut two_finger_start_distance,
        &mut tap_moved,
    );
    if result != Gesture::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_detect_two_finger_gesture_one_contact() -> TestResult {
    let tracked = [TrackedContact {
        id: 0,
        start_x: 100,
        start_y: 100,
        current_x: 100,
        current_y: 100,
        active: true,
        is_palm: false,
    }];
    let mut state = TouchpadState::default();
    let mut gesture_active = false;
    let mut two_finger_start_distance = 0;
    let mut tap_moved = false;

    let result = detect_two_finger_gesture(
        &tracked,
        &mut state,
        &mut gesture_active,
        &mut two_finger_start_distance,
        &mut tap_moved,
    );
    if result != Gesture::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_detect_three_finger_gesture_no_contacts() -> TestResult {
    let tracked = [];
    let result = detect_three_finger_gesture(&tracked);
    if result != Gesture::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_detect_four_finger_gesture_no_contacts() -> TestResult {
    let tracked = [];
    let result = detect_four_finger_gesture(&tracked);
    if result != Gesture::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_acceleration_small_delta() -> TestResult {
    let result = apply_acceleration(3, 2, 10);
    if result != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_acceleration_medium_delta() -> TestResult {
    let result = apply_acceleration(15, 2, 10);
    if result != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_acceleration_large_delta() -> TestResult {
    let result = apply_acceleration(30, 2, 10);
    if result != 120 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_acceleration_very_large_delta() -> TestResult {
    let result = apply_acceleration(60, 2, 10);
    if result != 360 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_apply_acceleration_negative() -> TestResult {
    let result = apply_acceleration(-30, 2, 10);
    if result != -120 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_distance_zero() -> TestResult {
    let d = distance(0, 0, 0, 0);
    if d != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_distance_horizontal() -> TestResult {
    let d = distance(0, 0, 10, 0);
    if d != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_distance_vertical() -> TestResult {
    let d = distance(0, 0, 0, 10);
    if d != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_distance_diagonal() -> TestResult {
    let d = distance(0, 0, 3, 4);
    if d != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_zero() -> TestResult {
    if isqrt(0) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_one() -> TestResult {
    if isqrt(1) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_four() -> TestResult {
    if isqrt(4) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_nine() -> TestResult {
    if isqrt(9) != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_sixteen() -> TestResult {
    if isqrt(16) != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_large() -> TestResult {
    if isqrt(100) != 10 {
        return TestResult::Fail;
    }
    if isqrt(10000) != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_isqrt_non_perfect() -> TestResult {
    if isqrt(5) != 2 {
        return TestResult::Fail;
    }
    if isqrt(8) != 2 {
        return TestResult::Fail;
    }
    if isqrt(15) != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_state_contacts_array_size() -> TestResult {
    let state = TouchpadState::default();
    if state.contacts.len() != MAX_CONTACTS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touch_point_clone() -> TestResult {
    let point =
        TouchPoint { id: 1, x: 100, y: 200, tip: true, pressure: 50, width: 10, height: 10 };
    let cloned = point.clone();
    if cloned.id != point.id {
        return TestResult::Fail;
    }
    if cloned.x != point.x {
        return TestResult::Fail;
    }
    if cloned.y != point.y {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tracked_contact_clone() -> TestResult {
    let contact = TrackedContact {
        id: 1,
        start_x: 100,
        start_y: 100,
        current_x: 150,
        current_y: 150,
        active: true,
        is_palm: false,
    };
    let cloned = contact.clone();
    if cloned.id != contact.id {
        return TestResult::Fail;
    }
    if cloned.active != contact.active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gesture_clone() -> TestResult {
    let gesture = Gesture::TwoFingerScroll { dx: 5, dy: 10 };
    let cloned = gesture.clone();
    if gesture != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_touchpad_state_clone() -> TestResult {
    let mut state = TouchpadState::default();
    state.delta_x = 10;
    state.delta_y = 20;
    state.buttons = 1;
    let cloned = state.clone();
    if cloned.delta_x != 10 {
        return TestResult::Fail;
    }
    if cloned.delta_y != 20 {
        return TestResult::Fail;
    }
    if cloned.buttons != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
