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
use nonos_app_skeleton::{clipboard_paste_line, EventOutcome, InputEvent, InputKind};

use super::state::{Screen, State};
use super::ui::hit::Target;
use super::ui::hover::target_at;
use super::ui::table_geom;

#[path = "event_apply.rs"]
mod event_apply;
#[path = "event_hover.rs"]
mod event_hover;
#[path = "event_key.rs"]
mod event_key;
#[path = "event_scroll.rs"]
mod event_scroll;

pub use event_hover::rehover;

pub fn on_event(state: &mut State, event: InputEvent) -> EventOutcome {
    if let Some(out) = event_hover::on_hover(state, &event) {
        return out;
    }
    if event.kind == InputKind::ButtonDown {
        return event_hover::press(state, event.x, event.y);
    }
    if event.kind == InputKind::Wheel {
        let delta = if event.delta_y > 0 { -3 } else { 3 };
        if state.screen == Screen::Security {
            state.alert_scroll_by(delta);
        } else {
            state.scroll_by(delta);
        }
        rehover(state);
        return EventOutcome::Repaint;
    }
    if !event.is_key_down() {
        return EventOutcome::Idle;
    }
    if state.query_focused() && is_paste(&event) {
        let out = paste(state);
        rehover(state);
        return out;
    }
    let out = event_key::key(state, event.code);
    rehover(state);
    out
}

fn paste(state: &mut State) -> EventOutcome {
    // Room for more than the field holds, so a longer line is seen as cut.
    let mut buf = [0u8; 128];
    match clipboard_paste_line(&mut buf) {
        Ok(Some(line)) => state.paste_into_query(line.text),
        Ok(None) => state.notice = b"paste: the clipboard holds no text",
        Err(_) => state.notice = b"paste: the clipboard is not available",
    }
    EventOutcome::Repaint
}

// The whole click path: ask the shared hit test what the frame drew under the
// pointer, then act on the answer. Not one coordinate is derived here, which is
// the only reason a click cannot land on something other than what was painted.
fn click(state: &mut State, x: i32, y: i32) -> EventOutcome {
    let Some(target) = target_at(state, x, y) else {
        return EventOutcome::Idle;
    };
    state.focus_search(matches!(&target, Target::Search));
    match target {
        Target::Search => {}
        Target::Nav(screen) => state.set_screen(screen),
        Target::Sort(col) => {
            if let Some(sort) = table_geom::sort_for(col) {
                state.set_sort(sort);
            }
        }
        Target::Row(index) | Target::Matrix(index) => state.select_visible(index),
        Target::Finding(index) => {
            state.alert_sel = index;
            state.jump_to_alert();
        }
        Target::Filter(filter) => state.set_filter(filter),
        Target::EndProcess => state.end_selected(),
    }
    EventOutcome::Repaint
}
