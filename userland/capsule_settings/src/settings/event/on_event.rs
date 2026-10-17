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

use nonos_app_skeleton::input::text::is_paste;
use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind, MOD_ALT, MOD_CTRL, MOD_META};

use crate::settings::section::Section;
use crate::settings::state::{searching, view_h, State};
use crate::settings::ui::bytes::as_str;
use crate::settings::ui::results;
use crate::settings::ui::results_geom;
use crate::settings::ui::scroll::max_scroll;

use super::on_event_browsing::on_event_browsing;
use super::on_event_editing::on_event_editing;
use super::on_event_wifi::on_event_wifi;
use super::on_hover::{on_hover, rehover};
use super::on_pointer::on_pointer;
use super::on_search_key::on_search_key;
use super::paste::on_paste;

// Pixels moved per wheel notch.
const WHEEL_STEP: u32 = 48;

pub fn on_event(state: &mut State, event: InputEvent) -> EventOutcome {
    if let Some(out) = on_hover(state, &event) {
        return out;
    }
    if event.kind == InputKind::ButtonDown {
        return press(state, event.x, event.y);
    }
    if event.kind == InputKind::Wheel && !state.editing {
        let out = wheel(state, event.delta_y);
        rehover(state);
        return out;
    }
    if !event.is_key_down() {
        return EventOutcome::Idle;
    }
    // Ctrl+V or Shift+Insert into whichever field has the keyboard.
    if is_paste(&event) {
        if let Some(out) = on_paste(state) {
            return out;
        }
    }
    if state.search_focused {
        return on_search_key(state, &event);
    }
    if state.editing {
        // A chord is a command, and the editor's only one is paste: Ctrl with
        // a letter typed the letter into the value.
        if event.flags & (MOD_CTRL | MOD_ALT | MOD_META) != 0 {
            return EventOutcome::Idle;
        }
        return on_event_editing(state, event.code);
    }
    if state.section == Section::Wifi {
        return on_event_wifi(state, event.code);
    }
    on_event_browsing(state, event.code)
}

/// A press clicks at once, as it always has; the pointer is told first, so
/// the repaint the click asks for already draws the press.
fn press(state: &mut State, x: i32, y: i32) -> EventOutcome {
    state.pointer.pressed(x, y);
    let out = on_pointer(state, x, y);
    if rehover(state) == EventOutcome::Repaint && out == EventOutcome::Idle {
        return EventOutcome::Repaint;
    }
    out
}

fn wheel(state: &mut State, delta_y: i32) -> EventOutcome {
    let steps = delta_y.unsigned_abs().min(10) * WHEEL_STEP;
    if steps == 0 {
        return EventOutcome::Idle;
    }
    if searching(state) {
        return wheel_results(state, delta_y, steps);
    }
    let i = state.section.index();
    let limit = max_scroll(state, view_h(state));
    state.scroll_px[i] = if delta_y > 0 {
        state.scroll_px[i].saturating_sub(steps)
    } else {
        (state.scroll_px[i] + steps).min(limit)
    };
    EventOutcome::Repaint
}

fn wheel_results(state: &mut State, delta_y: i32, steps: u32) -> EventOutcome {
    let n = results::count(as_str(state.search.as_slice()));
    let limit = results_geom::max_scroll(n, view_h(state));
    state.search_scroll = if delta_y > 0 {
        state.search_scroll.saturating_sub(steps)
    } else {
        (state.search_scroll + steps).min(limit)
    };
    EventOutcome::Repaint
}
