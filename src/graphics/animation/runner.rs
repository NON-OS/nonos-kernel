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

use super::{timing, Animation};
use core::sync::atomic::{AtomicU8, Ordering};

pub const MAX_ANIMATIONS: usize = 32;

static ACTIVE_COUNT: AtomicU8 = AtomicU8::new(0);
static mut ANIMATIONS: [Option<AnimationSlot>; MAX_ANIMATIONS] = [None; MAX_ANIMATIONS];

#[derive(Clone, Copy)]
pub struct AnimationSlot {
    pub id: u16,
    pub animation: Animation,
    pub callback_id: u16,
}

#[allow(static_mut_refs)]
pub fn start_animation(id: u16, animation: Animation, callback_id: u16) -> bool {
    let current_time = timing::current_time();
    unsafe {
        for slot in ANIMATIONS.iter_mut() {
            if slot.is_none() {
                let mut anim = animation;
                anim.start(current_time);
                *slot = Some(AnimationSlot { id, animation: anim, callback_id });
                ACTIVE_COUNT.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }
    false
}

#[allow(static_mut_refs)]
pub fn stop_animation(id: u16) {
    unsafe {
        for slot in ANIMATIONS.iter_mut() {
            if let Some(s) = slot {
                if s.id == id {
                    *slot = None;
                    ACTIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }
}

#[allow(static_mut_refs)]
pub fn get_animation_value(id: u16) -> Option<f32> {
    let current_time = timing::current_time();
    unsafe {
        for slot in ANIMATIONS.iter() {
            if let Some(s) = slot {
                if s.id == id {
                    return Some(s.animation.current_value(current_time));
                }
            }
        }
    }
    None
}

#[allow(static_mut_refs)]
pub fn update_animations() -> u8 {
    let current_time = timing::current_time();
    let mut completed = 0u8;
    unsafe {
        for slot in ANIMATIONS.iter_mut() {
            if let Some(s) = slot {
                if s.animation.is_complete(current_time) {
                    s.animation.complete();
                    completed += 1;
                    *slot = None;
                    ACTIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
    completed
}

pub fn active_count() -> u8 {
    ACTIVE_COUNT.load(Ordering::Relaxed)
}
pub fn has_active_animations() -> bool {
    active_count() > 0
}
