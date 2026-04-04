use crate::input::i2c_hid::touchpad::types::{
    TouchPoint, TouchpadState, Gesture, TrackedContact,
};
use crate::input::i2c_hid::touchpad::constants::{
    MAX_CONTACTS, PALM_MIN_PRESSURE, PALM_MIN_AREA, PALM_EDGE_THRESHOLD,
    TAP_TIMEOUT_US, DOUBLE_TAP_TIMEOUT_US, SCROLL_THRESHOLD, PINCH_THRESHOLD, SWIPE_THRESHOLD,
};
use crate::input::i2c_hid::touchpad::gesture::{
    detect_two_finger_gesture, detect_three_finger_gesture, detect_four_finger_gesture,
    is_tap_event, is_double_tap, tap_timing_config,
};
use crate::input::i2c_hid::touchpad::util::{apply_acceleration, distance, isqrt};

#[test]
fn test_touch_point_default() {
    let point = TouchPoint::default();
    assert_eq!(point.id, 0);
    assert_eq!(point.x, 0);
    assert_eq!(point.y, 0);
    assert!(!point.tip);
    assert_eq!(point.pressure, 0);
    assert_eq!(point.width, 0);
    assert_eq!(point.height, 0);
}

#[test]
fn test_touch_point_area() {
    let point = TouchPoint {
        id: 1,
        x: 100,
        y: 200,
        tip: true,
        pressure: 50,
        width: 10,
        height: 20,
    };
    assert_eq!(point.area(), 200);
}

#[test]
fn test_touch_point_area_zero() {
    let point = TouchPoint::default();
    assert_eq!(point.area(), 0);
}

#[test]
fn test_touch_point_is_palm_by_area() {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: 500,
        tip: true,
        pressure: 50,
        width: 25,
        height: 20,
    };
    assert!(point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_touch_point_is_palm_by_pressure() {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: 500,
        tip: true,
        pressure: PALM_MIN_PRESSURE + 1,
        width: 5,
        height: 5,
    };
    assert!(point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_touch_point_is_palm_by_left_edge() {
    let point = TouchPoint {
        id: 1,
        x: PALM_EDGE_THRESHOLD - 1,
        y: 500,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    assert!(point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_touch_point_is_palm_by_right_edge() {
    let point = TouchPoint {
        id: 1,
        x: 1000 - PALM_EDGE_THRESHOLD + 1,
        y: 500,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    assert!(point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_touch_point_is_palm_by_top_edge() {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: PALM_EDGE_THRESHOLD - 1,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    assert!(point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_touch_point_is_palm_by_bottom_edge() {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: 1000 - PALM_EDGE_THRESHOLD + 1,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    assert!(point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_touch_point_not_palm() {
    let point = TouchPoint {
        id: 1,
        x: 500,
        y: 500,
        tip: true,
        pressure: 50,
        width: 5,
        height: 5,
    };
    assert!(!point.is_palm_candidate(1000, 1000));
}

#[test]
fn test_gesture_default() {
    let gesture = Gesture::default();
    assert_eq!(gesture, Gesture::None);
}

#[test]
fn test_gesture_variants() {
    assert_eq!(Gesture::None, Gesture::None);
    assert_eq!(Gesture::Tap, Gesture::Tap);
    assert_eq!(Gesture::DoubleTap, Gesture::DoubleTap);
    assert_eq!(Gesture::TwoFingerTap, Gesture::TwoFingerTap);
    assert_eq!(Gesture::ThreeFingerTap, Gesture::ThreeFingerTap);
}

#[test]
fn test_gesture_two_finger_scroll() {
    let gesture = Gesture::TwoFingerScroll { dx: 10, dy: 20 };
    match gesture {
        Gesture::TwoFingerScroll { dx, dy } => {
            assert_eq!(dx, 10);
            assert_eq!(dy, 20);
        }
        _ => panic!("Expected TwoFingerScroll"),
    }
}

#[test]
fn test_gesture_pinch_zoom() {
    let gesture = Gesture::PinchZoom { scale: 50 };
    match gesture {
        Gesture::PinchZoom { scale } => {
            assert_eq!(scale, 50);
        }
        _ => panic!("Expected PinchZoom"),
    }
}

#[test]
fn test_gesture_three_finger_swipes() {
    assert_eq!(Gesture::ThreeFingerSwipeLeft, Gesture::ThreeFingerSwipeLeft);
    assert_eq!(Gesture::ThreeFingerSwipeRight, Gesture::ThreeFingerSwipeRight);
    assert_eq!(Gesture::ThreeFingerSwipeUp, Gesture::ThreeFingerSwipeUp);
    assert_eq!(Gesture::ThreeFingerSwipeDown, Gesture::ThreeFingerSwipeDown);
}

#[test]
fn test_gesture_four_finger_swipes() {
    assert_eq!(Gesture::FourFingerSwipeUp, Gesture::FourFingerSwipeUp);
    assert_eq!(Gesture::FourFingerSwipeDown, Gesture::FourFingerSwipeDown);
}

#[test]
fn test_touchpad_state_default() {
    let state = TouchpadState::default();
    assert_eq!(state.delta_x, 0);
    assert_eq!(state.delta_y, 0);
    assert_eq!(state.buttons, 0);
    assert_eq!(state.contact_count, 0);
    assert_eq!(state.gesture, Gesture::None);
    assert_eq!(state.scroll_x, 0);
    assert_eq!(state.scroll_y, 0);
}

#[test]
fn test_tracked_contact_default() {
    let contact = TrackedContact::default();
    assert_eq!(contact.id, 0);
    assert_eq!(contact.start_x, 0);
    assert_eq!(contact.start_y, 0);
    assert_eq!(contact.current_x, 0);
    assert_eq!(contact.current_y, 0);
    assert!(!contact.active);
    assert!(!contact.is_palm);
}

#[test]
fn test_constants_max_contacts() {
    assert_eq!(MAX_CONTACTS, 10);
}

#[test]
fn test_constants_palm_detection() {
    assert_eq!(PALM_MIN_PRESSURE, 200);
    assert_eq!(PALM_MIN_AREA, 400);
    assert_eq!(PALM_EDGE_THRESHOLD, 50);
}

#[test]
fn test_constants_tap_timeouts() {
    assert_eq!(TAP_TIMEOUT_US, 200_000);
    assert_eq!(DOUBLE_TAP_TIMEOUT_US, 400_000);
}

#[test]
fn test_constants_gesture_thresholds() {
    assert_eq!(SCROLL_THRESHOLD, 10);
    assert_eq!(PINCH_THRESHOLD, 20);
    assert_eq!(SWIPE_THRESHOLD, 100);
}

#[test]
fn test_is_tap_event_short() {
    assert!(is_tap_event(0, TAP_TIMEOUT_US - 1));
}

#[test]
fn test_is_tap_event_too_long() {
    assert!(!is_tap_event(0, TAP_TIMEOUT_US + 1));
}

#[test]
fn test_is_double_tap_quick() {
    assert!(is_double_tap(0, DOUBLE_TAP_TIMEOUT_US - 1));
}

#[test]
fn test_is_double_tap_too_slow() {
    assert!(!is_double_tap(0, DOUBLE_TAP_TIMEOUT_US + 1));
}

#[test]
fn test_tap_timing_config() {
    let (tap, double_tap) = tap_timing_config();
    assert_eq!(tap, TAP_TIMEOUT_US);
    assert_eq!(double_tap, DOUBLE_TAP_TIMEOUT_US);
}

#[test]
fn test_detect_two_finger_gesture_no_contacts() {
    let tracked = [];
    let mut state = TouchpadState::default();
    let mut gesture_active = false;
    let mut two_finger_start_distance = 0;
    let mut tap_moved = false;

    let result = detect_two_finger_gesture(
        &tracked, &mut state, &mut gesture_active,
        &mut two_finger_start_distance, &mut tap_moved,
    );
    assert_eq!(result, Gesture::None);
}

#[test]
fn test_detect_two_finger_gesture_one_contact() {
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
        &tracked, &mut state, &mut gesture_active,
        &mut two_finger_start_distance, &mut tap_moved,
    );
    assert_eq!(result, Gesture::None);
}

#[test]
fn test_detect_three_finger_gesture_no_contacts() {
    let tracked = [];
    let result = detect_three_finger_gesture(&tracked);
    assert_eq!(result, Gesture::None);
}

#[test]
fn test_detect_four_finger_gesture_no_contacts() {
    let tracked = [];
    let result = detect_four_finger_gesture(&tracked);
    assert_eq!(result, Gesture::None);
}

#[test]
fn test_apply_acceleration_small_delta() {
    let result = apply_acceleration(3, 2, 10);
    assert_eq!(result, 3);
}

#[test]
fn test_apply_acceleration_medium_delta() {
    let result = apply_acceleration(15, 2, 10);
    assert_eq!(result, 30);
}

#[test]
fn test_apply_acceleration_large_delta() {
    let result = apply_acceleration(30, 2, 10);
    assert_eq!(result, 120);
}

#[test]
fn test_apply_acceleration_very_large_delta() {
    let result = apply_acceleration(60, 2, 10);
    assert_eq!(result, 360);
}

#[test]
fn test_apply_acceleration_negative() {
    let result = apply_acceleration(-30, 2, 10);
    assert_eq!(result, -120);
}

#[test]
fn test_distance_zero() {
    let d = distance(0, 0, 0, 0);
    assert_eq!(d, 0);
}

#[test]
fn test_distance_horizontal() {
    let d = distance(0, 0, 10, 0);
    assert_eq!(d, 10);
}

#[test]
fn test_distance_vertical() {
    let d = distance(0, 0, 0, 10);
    assert_eq!(d, 10);
}

#[test]
fn test_distance_diagonal() {
    let d = distance(0, 0, 3, 4);
    assert_eq!(d, 5);
}

#[test]
fn test_isqrt_zero() {
    assert_eq!(isqrt(0), 0);
}

#[test]
fn test_isqrt_one() {
    assert_eq!(isqrt(1), 1);
}

#[test]
fn test_isqrt_four() {
    assert_eq!(isqrt(4), 2);
}

#[test]
fn test_isqrt_nine() {
    assert_eq!(isqrt(9), 3);
}

#[test]
fn test_isqrt_sixteen() {
    assert_eq!(isqrt(16), 4);
}

#[test]
fn test_isqrt_large() {
    assert_eq!(isqrt(100), 10);
    assert_eq!(isqrt(10000), 100);
}

#[test]
fn test_isqrt_non_perfect() {
    assert_eq!(isqrt(5), 2);
    assert_eq!(isqrt(8), 2);
    assert_eq!(isqrt(15), 3);
}

#[test]
fn test_touchpad_state_contacts_array_size() {
    let state = TouchpadState::default();
    assert_eq!(state.contacts.len(), MAX_CONTACTS);
}

#[test]
fn test_touch_point_clone() {
    let point = TouchPoint {
        id: 1,
        x: 100,
        y: 200,
        tip: true,
        pressure: 50,
        width: 10,
        height: 10,
    };
    let cloned = point.clone();
    assert_eq!(cloned.id, point.id);
    assert_eq!(cloned.x, point.x);
    assert_eq!(cloned.y, point.y);
}

#[test]
fn test_tracked_contact_clone() {
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
    assert_eq!(cloned.id, contact.id);
    assert_eq!(cloned.active, contact.active);
}

#[test]
fn test_gesture_clone() {
    let gesture = Gesture::TwoFingerScroll { dx: 5, dy: 10 };
    let cloned = gesture.clone();
    assert_eq!(gesture, cloned);
}

#[test]
fn test_touchpad_state_clone() {
    let mut state = TouchpadState::default();
    state.delta_x = 10;
    state.delta_y = 20;
    state.buttons = 1;
    let cloned = state.clone();
    assert_eq!(cloned.delta_x, 10);
    assert_eq!(cloned.delta_y, 20);
    assert_eq!(cloned.buttons, 1);
}
