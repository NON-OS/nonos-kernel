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

//! Keys and pointer presses sent to the page's scripts.
//!
//! A page heard a click and typing into a field, and nothing else: no
//! keydown or keyup, no mousedown, and a click with no position. Its own
//! widgets (a dialog closed with Esc, a search box that runs on Enter, a
//! carousel on the arrows, a menu opened where it was pressed) had nothing
//! to answer.

use nonos_app_skeleton::{
    EventOutcome, InputEvent, KEY_ENTER, MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT,
};
use nonos_qjs::{Key, Press};

use crate::browser::dom::node::NodeKind;
use crate::browser::omnibox::{text_char, Focus};
use crate::browser::state::{State, View};

use super::key_names::key_names;

/* The window's modifier flags as an event's MOD_* bits. */
fn mods(flags: u16) -> u8 {
    let bit = |m: u16, b: u8| if flags & m != 0 { b } else { 0 };
    bit(MOD_SHIFT, nonos_qjs::MOD_SHIFT)
        | bit(MOD_CTRL, nonos_qjs::MOD_CTRL)
        | bit(MOD_ALT, nonos_qjs::MOD_ALT)
        | bit(MOD_META, nonos_qjs::MOD_META)
}

/* Where a key goes: the focused field, else the body, as in other
 * browsers. None when there is no page to send it to. */
fn key_target(state: &State) -> Option<i32> {
    state.focus.or_else(|| body(state)).map(|n| n as i32)
}

/* The page hears a key that was pressed while it has the keyboard:
 * keydown, then keypress when the key types a character or is Enter.
 * Answers true when a listener cancelled either, and the browser then
 * leaves the key alone (no typing, scrolling, Tab or submit). */
pub(super) fn page_keydown(state: &mut State, event: InputEvent) -> bool {
    let Some(target) = key_target(state) else { return false };
    let Some(engine) = state.engine.as_ref() else { return false };
    let names = key_names(event.code);
    let key = Key {
        key: &names.key,
        code: &names.code,
        key_code: names.key_code,
        mods: mods(event.flags),
    };
    let fired = engine.dispatch_key(target, "keydown", &key);
    let mut cancelled = fired > 0 && engine.default_prevented();
    let mut ran = fired > 0;
    /* keypress carries the character's own code, 13 for Enter. */
    let typed = match event.code {
        KEY_ENTER => Some(13),
        code => text_char(code, event.flags).map(|c| c as i32),
    };
    if let (false, Some(ch)) = (cancelled, typed) {
        let press = Key { key_code: ch, ..key };
        let fired = engine.dispatch_key(target, "keypress", &press);
        cancelled = fired > 0 && engine.default_prevented();
        ran |= fired > 0;
    }
    if ran {
        state.track.js_dirty = true;
    }
    super::script_nav::take_script_nav(state);
    cancelled
}

/// A key let go while the page has the keyboard: the page hears keyup.
pub(super) fn on_keyup(state: &mut State, event: InputEvent) -> EventOutcome {
    let ours = state.view == View::Page && !state.on_own && state.ui.kbd == Focus::Page;
    if !ours || state.settings_open || state.ui.select.is_some() {
        return EventOutcome::Idle;
    }
    let Some(target) = key_target(state) else { return EventOutcome::Idle };
    let Some(engine) = state.engine.as_ref() else { return EventOutcome::Idle };
    let names = key_names(event.code);
    let key = Key {
        key: &names.key,
        code: &names.code,
        key_code: names.key_code,
        mods: mods(event.flags),
    };
    if engine.dispatch_key(target, "keyup", &key) > 0 {
        state.track.js_dirty = true;
    }
    super::script_nav::take_script_nav(state);
    EventOutcome::Idle
}

/// A press at page-area point (`x`, `y`) from window event `event`, as
/// the page's events carry it. `button` follows the window's codes: 2 is
/// the second button, 3 or 4 the middle one, anything else the main one.
pub(super) fn press_at(event: &InputEvent, x: i32, y: i32) -> Press {
    let (button, held) = match event.code {
        2 => (2, 2),
        3 | 4 => (1, 4),
        _ => (0, 1),
    };
    Press { x, y, button, buttons: held, mods: mods(event.flags) }
}

/* The page hears a press on `node` before its click: pointerdown and
 * mousedown with the button held, then pointerup and mouseup. The whole
 * press is sent when the button goes down, as the click is: a touch
 * delivers no release, and a click that waited for one would never come.
 * So mouseup comes before click, as in other browsers, but at once; no
 * mousemove is sent between them, and a drag is not seen. */
pub(super) fn page_press(state: &mut State, node: usize, press: &Press) {
    let Some(engine) = state.engine.as_ref() else { return };
    let up = Press { buttons: 0, ..*press };
    let mut ran = 0;
    ran += engine.dispatch_press(node as i32, "pointerdown", press);
    ran += engine.dispatch_press(node as i32, "mousedown", press);
    ran += engine.dispatch_press(node as i32, "pointerup", &up);
    ran += engine.dispatch_press(node as i32, "mouseup", &up);
    if ran > 0 {
        state.track.js_dirty = true;
    }
}

/// The body, where a press on no element lands.
pub(super) fn body(state: &State) -> Option<usize> {
    let dom = state.page_dom.as_ref()?;
    dom.nodes.iter().position(|n| n.kind == NodeKind::Element && n.tag == "body")
}
