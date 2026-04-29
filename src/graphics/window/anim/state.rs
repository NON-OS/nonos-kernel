// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::animation::{apply_easing, Easing};
use crate::time::timestamp_millis;

const MAX_ANIMATIONS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AnimationType {
    Open,
    Close,
    Minimize,
    Restore,
    Resize,
    Move,
}

#[derive(Clone, Copy)]
pub struct WindowAnimation {
    pub window_id: u32,
    pub anim_type: AnimationType,
    pub start_time: u64,
    pub duration_ms: u64,
    pub easing: Easing,
    pub start_x: i32,
    pub start_y: i32,
    pub start_w: u32,
    pub start_h: u32,
    pub end_x: i32,
    pub end_y: i32,
    pub end_w: u32,
    pub end_h: u32,
    pub start_alpha: f32,
    pub end_alpha: f32,
    pub active: bool,
}

impl WindowAnimation {
    pub const fn empty() -> Self {
        Self {
            window_id: 0,
            anim_type: AnimationType::Open,
            start_time: 0,
            duration_ms: 200,
            easing: Easing::EaseOut,
            start_x: 0,
            start_y: 0,
            start_w: 0,
            start_h: 0,
            end_x: 0,
            end_y: 0,
            end_w: 0,
            end_h: 0,
            start_alpha: 0.0,
            end_alpha: 1.0,
            active: false,
        }
    }

    pub fn progress(&self) -> f32 {
        let elapsed = timestamp_millis().saturating_sub(self.start_time);
        let t = (elapsed as f32) / (self.duration_ms as f32);
        apply_easing(t.min(1.0), self.easing)
    }

    pub fn is_complete(&self) -> bool {
        timestamp_millis().saturating_sub(self.start_time) >= self.duration_ms
    }
}

pub(super) static mut ANIMATIONS: [WindowAnimation; MAX_ANIMATIONS] = [WindowAnimation::empty(); MAX_ANIMATIONS];

pub(super) fn add_animation(anim: WindowAnimation) {
    use core::ptr::addr_of_mut;
    unsafe {
        for slot in (*addr_of_mut!(ANIMATIONS)).iter_mut() {
            if slot.window_id == anim.window_id {
                *slot = anim;
                return;
            }
        }
        for slot in (*addr_of_mut!(ANIMATIONS)).iter_mut() {
            if !slot.active {
                *slot = anim;
                return;
            }
        }
    }
}
