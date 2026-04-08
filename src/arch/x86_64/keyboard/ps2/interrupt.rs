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

use super::mouse::MousePacket;
use super::globals::{CONTROLLER, MOUSE, DECODER};
use super::super::{input, keymap};

pub fn handle_interrupt() {
    let ctrl = CONTROLLER.lock();
    while ctrl.has_data() {
        let data = ctrl.read_data_nowait();
        if ctrl.is_mouse_data() {
            let mut m = MOUSE.lock();
            if let Some(p) = m.process_byte(data) { handle_mouse_packet(p); }
        } else {
            let mut dec = DECODER.lock();
            if let Some((code, released, extended)) = dec.decode(data) { handle_key_event(code, released, extended); }
        }
    }
}

fn handle_key_event(code: u8, released: bool, extended: bool) {
    let ev = input::KeyEvent { scan_code: code, pressed: !released, modifiers: input::Modifiers::NONE, repeat_count: 0 };
    let kind = if released { input::InputEventKind::KeyRelease(ev) } else { input::InputEventKind::KeyPress(ev) };
    let _ = input::push_event(input::InputEvent::new(kind));
    keymap::update_modifiers(code, released, extended);
}

fn handle_mouse_packet(p: MousePacket) {
    if p.dx != 0 || p.dy != 0 {
        let _ = input::push_event(input::InputEvent::new(input::InputEventKind::MouseMove(input::MouseMoveEvent { dx: p.dx, dy: p.dy, abs_x: None, abs_y: None })));
    }
    if p.dz != 0 {
        let _ = input::push_event(input::InputEvent::new(input::InputEventKind::MouseScroll(input::MouseScrollEvent { delta_y: p.dz, delta_x: 0 })));
    }
}
