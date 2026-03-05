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

use super::constants::{MAX_CONTACTS, PALM_MIN_PRESSURE, PALM_MIN_AREA, PALM_EDGE_THRESHOLD};

#[derive(Debug, Clone, Copy, Default)]
pub struct TouchPoint {
    pub id: u8,
    pub x: i32,
    pub y: i32,
    pub tip: bool,
    pub pressure: u8,
    pub width: u8,
    pub height: u8,
}

impl TouchPoint {
    pub fn area(&self) -> u16 {
        (self.width as u16) * (self.height as u16)
    }

    pub fn is_palm_candidate(&self, max_x: i32, max_y: i32) -> bool {
        if self.area() > PALM_MIN_AREA {
            return true;
        }
        if self.pressure > PALM_MIN_PRESSURE {
            return true;
        }
        if self.x < PALM_EDGE_THRESHOLD || self.x > max_x - PALM_EDGE_THRESHOLD {
            return true;
        }
        if self.y < PALM_EDGE_THRESHOLD || self.y > max_y - PALM_EDGE_THRESHOLD {
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gesture {
    None,
    Tap,
    DoubleTap,
    TwoFingerTap,
    ThreeFingerTap,
    TwoFingerScroll { dx: i32, dy: i32 },
    PinchZoom { scale: i32 },
    ThreeFingerSwipeLeft,
    ThreeFingerSwipeRight,
    ThreeFingerSwipeUp,
    ThreeFingerSwipeDown,
    FourFingerSwipeUp,
    FourFingerSwipeDown,
}

impl Default for Gesture {
    fn default() -> Self {
        Gesture::None
    }
}

#[derive(Debug, Clone, Default)]
pub struct TouchpadState {
    pub delta_x: i32,
    pub delta_y: i32,
    pub buttons: u8,
    pub contact_count: u8,
    pub contacts: [TouchPoint; MAX_CONTACTS],
    pub gesture: Gesture,
    pub scroll_x: i32,
    pub scroll_y: i32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TrackedContact {
    pub id: u8,
    pub start_x: i32,
    pub start_y: i32,
    pub current_x: i32,
    pub current_y: i32,
    pub active: bool,
    pub is_palm: bool,
}
