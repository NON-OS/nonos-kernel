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

use nonos_app_skeleton::{
    EventOutcome, InputEvent, InputKind, KEY_DOWN, KEY_END, KEY_ESC, KEY_HOME, KEY_PAGE_DOWN,
    KEY_PAGE_UP, KEY_TAB, KEY_UP, MOD_SHIFT,
};

use super::on_arrow_down::on_arrow_down;
use super::on_arrow_up::on_arrow_up;
use super::on_end::on_end;
use super::on_esc::on_esc;
use super::on_home::on_home;
use super::on_page_down::on_page_down;
use super::on_page_up::on_page_up;
use super::on_pointer_button::on_pointer_button;
use super::on_shift_tab::on_shift_tab;
use super::on_tab::on_tab;
use crate::about::scroll_wheel::wheel_to;
use crate::about::state::State;
use crate::about::ui::hover::on_pointer;

pub fn on_event(state: &mut State, event: InputEvent) -> EventOutcome {
    if let Some(out) = on_pointer(&mut state.pointer, &mut state.hover, &event) {
        return out;
    }
    if event.kind == InputKind::ButtonDown {
        return on_pointer_button(state, event.x, event.y);
    }
    // The wheel was delivered and dropped, so the longer screens (Licenses,
    // Proofs, Trust) could only be read with the keys.
    if event.kind == InputKind::Wheel {
        let next = wheel_to(state.scroll, state.max_scroll(), event.delta_y);
        if next == state.scroll {
            return EventOutcome::Idle;
        }
        state.scroll = next;
        return EventOutcome::Repaint;
    }
    if !event.is_key_down() {
        return EventOutcome::Idle;
    }
    match event.code {
        KEY_ESC => on_esc(),
        KEY_TAB if event.flags & MOD_SHIFT != 0 => on_shift_tab(state),
        KEY_TAB => on_tab(state),
        KEY_UP => on_arrow_up(state),
        KEY_DOWN => on_arrow_down(state),
        KEY_PAGE_UP => on_page_up(state),
        KEY_PAGE_DOWN => on_page_down(state),
        KEY_HOME => on_home(state),
        KEY_END => on_end(state),
        _ => EventOutcome::Idle,
    }
}
