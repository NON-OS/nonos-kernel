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

use core::ptr::{addr_of, addr_of_mut};
use super::state::{WindowAnimation, ANIMATIONS};

pub fn has_animation(window_id: u32) -> bool {
    unsafe { (*addr_of!(ANIMATIONS)).iter().any(|a| a.active && a.window_id == window_id) }
}

pub fn is_animating() -> bool {
    unsafe { (*addr_of!(ANIMATIONS)).iter().any(|a| a.active) }
}

pub fn get_animation(window_id: u32) -> Option<&'static WindowAnimation> {
    unsafe { (*addr_of!(ANIMATIONS)).iter().find(|a| a.active && a.window_id == window_id) }
}

pub fn remove_animation(window_id: u32) {
    unsafe {
        for slot in (*addr_of_mut!(ANIMATIONS)).iter_mut() {
            if slot.window_id == window_id {
                slot.active = false;
            }
        }
    }
}

pub fn tick_animations() {
    unsafe {
        for slot in (*addr_of_mut!(ANIMATIONS)).iter_mut() {
            if slot.active && slot.is_complete() {
                slot.active = false;
            }
        }
    }
}
