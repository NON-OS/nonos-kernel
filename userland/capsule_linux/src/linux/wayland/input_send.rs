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

//! One input event, written to the client.

use nonos_app_skeleton::scroll::MAX_NOTCHES;

use crate::linux::guest::Guest;

use super::input_enter::enter_once;
use super::out::Event;

/// wl_pointer: motion 2, button 3, axis 4, frame 5.
const POINTER_MOTION: u16 = 2;
const POINTER_BUTTON: u16 = 3;
const POINTER_AXIS: u16 = 4;
const POINTER_FRAME: u16 = 5;

/// Wayland carries a surface coordinate as 24.8 fixed point.
fn fixed(value: i32) -> u32 {
    (value << 8) as u32
}

pub fn motion(guest: &mut Guest, x: i32, y: i32) {
    let Some(id) = guest.scene.pointer else { return };
    enter_once(guest, id, x, y);
    let time = time_ms();
    Event::new(id, POINTER_MOTION)
        .u32(time)
        .u32(fixed(x))
        .u32(fixed(y))
        .send(&mut guest.display.to_client);
    Event::new(id, POINTER_FRAME).send(&mut guest.display.to_client);
}

pub fn button(guest: &mut Guest, code: u32, state: u32) {
    let Some(id) = guest.scene.pointer else { return };
    let serial = guest.scene.next_serial();
    let time = time_ms();
    Event::new(id, POINTER_BUTTON)
        .u32(serial)
        .u32(time)
        .u32(code)
        .u32(state)
        .send(&mut guest.display.to_client);
    Event::new(id, POINTER_FRAME).send(&mut guest.display.to_client);
}

/// A wheel event as a vertical wl_pointer.axis, 10 surface units per notch.
/// The 10 is hand-synced with the qwen client, which divides it back out.
/// Wayland's positive is toward the end, the opposite of NONOS `delta_y`.
pub fn axis(guest: &mut Guest, x: i32, y: i32, delta_y: i32) {
    let Some(id) = guest.scene.pointer else { return };
    if delta_y == 0 {
        return;
    }
    let notches = delta_y.clamp(-(MAX_NOTCHES as i32), MAX_NOTCHES as i32);
    enter_once(guest, id, x, y);
    let time = time_ms();
    Event::new(id, POINTER_AXIS)
        .u32(time)
        .u32(0)
        .u32(fixed(-notches * 10))
        .send(&mut guest.display.to_client);
    Event::new(id, POINTER_FRAME).send(&mut guest.display.to_client);
}

fn time_ms() -> u32 {
    crate::linux::call::family_ms() as u32
}
