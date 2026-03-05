// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use alloc::vec::Vec;
use super::constants::{SCROLL_THRESHOLD, PINCH_THRESHOLD, SWIPE_THRESHOLD, TAP_TIMEOUT_US, DOUBLE_TAP_TIMEOUT_US};
use super::types::{Gesture, TouchpadState, TrackedContact};
use super::util::distance;

pub fn detect_two_finger_gesture(
    tracked_contacts: &[TrackedContact],
    state: &mut TouchpadState,
    gesture_active: &mut bool,
    two_finger_start_distance: &mut i32,
    tap_moved: &mut bool,
) -> Gesture {
    let contacts: Vec<_> = tracked_contacts.iter()
        .filter(|tc| tc.active)
        .take(2)
        .collect();

    if contacts.len() < 2 {
        return Gesture::None;
    }

    let c1 = contacts[0];
    let c2 = contacts[1];

    let dx1 = c1.current_x - c1.start_x;
    let dy1 = c1.current_y - c1.start_y;
    let dx2 = c2.current_x - c2.start_x;
    let dy2 = c2.current_y - c2.start_y;

    let avg_dx = (dx1 + dx2) / 2;
    let avg_dy = (dy1 + dy2) / 2;

    if avg_dy.abs() > SCROLL_THRESHOLD || avg_dx.abs() > SCROLL_THRESHOLD {
        state.scroll_x = -avg_dx / 5;
        state.scroll_y = -avg_dy / 5;
        *tap_moved = true;
        return Gesture::TwoFingerScroll {
            dx: state.scroll_x,
            dy: state.scroll_y,
        };
    }

    let current_distance = distance(c1.current_x, c1.current_y, c2.current_x, c2.current_y);
    let start_distance = distance(c1.start_x, c1.start_y, c2.start_x, c2.start_y);

    if !*gesture_active {
        *two_finger_start_distance = start_distance;
        *gesture_active = true;
    }

    let distance_change = current_distance - *two_finger_start_distance;
    if distance_change.abs() > PINCH_THRESHOLD {
        *tap_moved = true;
        return Gesture::PinchZoom { scale: distance_change };
    }

    Gesture::None
}

pub fn detect_three_finger_gesture(tracked_contacts: &[TrackedContact]) -> Gesture {
    let contacts: Vec<_> = tracked_contacts.iter()
        .filter(|tc| tc.active)
        .take(3)
        .collect();

    if contacts.len() < 3 {
        return Gesture::None;
    }

    let mut total_dx = 0;
    let mut total_dy = 0;
    for c in &contacts {
        total_dx += c.current_x - c.start_x;
        total_dy += c.current_y - c.start_y;
    }
    let avg_dx = total_dx / 3;
    let avg_dy = total_dy / 3;

    if avg_dx.abs() > SWIPE_THRESHOLD && avg_dx.abs() > avg_dy.abs() {
        if avg_dx > 0 {
            return Gesture::ThreeFingerSwipeRight;
        } else {
            return Gesture::ThreeFingerSwipeLeft;
        }
    }

    if avg_dy.abs() > SWIPE_THRESHOLD && avg_dy.abs() > avg_dx.abs() {
        if avg_dy > 0 {
            return Gesture::ThreeFingerSwipeDown;
        } else {
            return Gesture::ThreeFingerSwipeUp;
        }
    }

    Gesture::None
}

pub fn detect_four_finger_gesture(tracked_contacts: &[TrackedContact]) -> Gesture {
    let contacts: Vec<_> = tracked_contacts.iter()
        .filter(|tc| tc.active)
        .take(4)
        .collect();

    if contacts.len() < 4 {
        return Gesture::None;
    }

    let mut total_dy = 0;
    for c in &contacts {
        total_dy += c.current_y - c.start_y;
    }
    let avg_dy = total_dy / 4;

    if avg_dy.abs() > SWIPE_THRESHOLD {
        if avg_dy > 0 {
            return Gesture::FourFingerSwipeDown;
        } else {
            return Gesture::FourFingerSwipeUp;
        }
    }

    Gesture::None
}

/// Check if a tap event occurred based on touch duration
pub fn is_tap_event(touch_start_us: u64, touch_end_us: u64) -> bool {
    let duration = touch_end_us.saturating_sub(touch_start_us);
    duration < TAP_TIMEOUT_US
}

/// Check if a double tap occurred based on timing between taps
pub fn is_double_tap(first_tap_us: u64, second_tap_us: u64) -> bool {
    let gap = second_tap_us.saturating_sub(first_tap_us);
    gap < DOUBLE_TAP_TIMEOUT_US
}

/// Get tap timing configuration
pub fn tap_timing_config() -> (u64, u64) {
    (TAP_TIMEOUT_US, DOUBLE_TAP_TIMEOUT_US)
}
