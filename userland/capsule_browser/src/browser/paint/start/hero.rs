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

use nonos_app_skeleton::{measure_ttf, PaintBuffer};
use nonos_libc::mk_time_millis;

use crate::browser::omnibox::Focus;
use crate::browser::paint::glyph::{self, Glyph};
use crate::browser::paint::{clip, field_text, tokens, FieldInk};
use crate::browser::shell::clock::hour_greeting;
use crate::browser::state::State;
use crate::browser::ui::start_geom::{pill_text, StartGeom};

const GREET_PX: f32 = 44.0;
const SUB_PX: f32 = 18.0;
const PILL_RADIUS: u32 = 26;
const RING: u32 = 2;
const SPREAD: u32 = 6;
const ICON: i32 = 20;
const ICON_X: i32 = 28;
const SUBLINE: &str = "Private by default.";
const HINT: &str = "Search or enter address";
const INK: FieldInk =
    FieldInk { text: tokens::INK, hint: tokens::MUTED, select: tokens::ACCENT_SOFT };

/// The sky band with the greeting, the search pill and the session badge.
pub fn paint(state: &State, g: &StartGeom, fb: &mut PaintBuffer) {
    clip::gradient_v(fb, g.hero, tokens::SKY, tokens::GROUND);
    let greet_right =
        centred(fb, hour_greeting(mk_time_millis()), g.greet_y, tokens::INK, GREET_PX);
    centred(fb, SUBLINE, g.sub_y, tokens::MUTED, SUB_PX);
    pill(state, g, fb);
    super::badge::paint(fb, g.hero, greet_right);
}

fn centred(fb: &mut PaintBuffer, s: &str, y: i32, argb: u32, px: f32) -> i32 {
    let x = (fb.width as i32 - measure_ttf(s, px)) / 2;
    fb.text_ttf(x, y, s, argb, px)
}

/// The address bar's twin: the same text, caret and selection, drawn in a
/// wide pill on the sky. Keystrokes repaint the whole start page with it.
fn pill(state: &State, g: &StartGeom, fb: &mut PaintBuffer) {
    let (p, Some(t)) = (g.pill, pill_text(g)) else { return };
    let (x, y, w, h) = (p.x as u32, p.y as u32, p.w as u32, p.h as u32);
    let focused = state.ui.kbd == Focus::Omnibox;
    fb.shadow_round(x, y, w, h, PILL_RADIUS, SPREAD, tokens::SHADOW);
    fb.fill_round(x, y, w, h, PILL_RADIUS, tokens::SURFACE);
    if focused {
        fb.stroke_round(x, y, w, h, PILL_RADIUS, RING, tokens::ACCENT);
    }
    glyph::draw(fb, Glyph::Search, p.x + ICON_X, p.y + p.h / 2, ICON, tokens::MUTED);
    let at = (focused, state.start_text_off(t.w));
    let boxed = (t.x as u32, t.y as u32, t.w as u32, t.h as u32);
    field_text(fb, boxed, &state.ui.omnibox, at, HINT, INK);
}
