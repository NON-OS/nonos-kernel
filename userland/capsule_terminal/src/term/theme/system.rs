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

//! The System theme: the terminal palette and the sixteen colours programs name,
//! worked out from the OS theme's roles. Each program colour takes a status ink
//! or a mix of inks, then steps towards the text until it clears 4.5:1 on the
//! ground, measured in all nine schemes and high contrast. Black and bright
//! black are for rules and dim text, so they only have to show.

use nonos_toolkit::theme::contrast::{at_least, BODY};
use nonos_toolkit::theme::derive::{mix, opaque};
use nonos_toolkit::theme::Roles;

use super::types::Theme;

/// How far, of 255, a selected cell moves from the ground towards the accent,
/// black from the ground towards the text, and a bright colour from its base
/// towards the text; and one step towards the text for a colour too faint.
const SELECTION: u8 = 64;
const BLACK: u8 = 40;
const BRIGHT: u8 = 64;
const STEP: u8 = 16;

pub fn theme(r: &Roles) -> Theme {
    let (bg, text) = (r.bg.argb(), r.text.argb());
    Theme {
        bg,
        fg: text,
        accent: legible(r.accent.argb(), bg, text),
        path: legible(r.accent_text.argb(), bg, text),
        dim: r.muted.argb(),
        ok: legible(r.ok.argb(), bg, text),
        err: legible(r.danger.argb(), bg, text),
        run: r.quiet.argb(),
        chrome_edge: r.border.argb(),
        selection: opaque(mix(bg, r.accent.argb(), SELECTION)),
    }
}

/// Red, green, yellow, blue, magenta, cyan, then their bright forms, with
/// black, white, bright black and bright white at the four ends.
pub fn ansi(r: &Roles) -> [u32; 16] {
    let (bg, text, accent, danger, ok) =
        (r.bg.argb(), r.text.argb(), r.accent.argb(), r.danger.argb(), r.ok.argb());
    let hues = [danger, ok, r.warn.argb(), accent, mix(danger, accent, 128), mix(accent, ok, 128)];
    let mut out = [text; 16];
    out[0] = mix(bg, text, BLACK);
    out[7] = legible(r.text_2.argb(), bg, text);
    out[8] = r.muted.argb();
    for (i, &hue) in hues.iter().enumerate() {
        out[1 + i] = legible(hue, bg, text);
        out[9 + i] = legible(mix(out[1 + i], text, BRIGHT), bg, text);
    }
    out
}

/// `c`, or the first step from it towards `text` that reads on `bg`.
fn legible(c: u32, bg: u32, text: u32) -> u32 {
    let mut steps = (0..=u8::MAX).step_by(STEP as usize).map(|t| mix(c, text, t));
    steps.find(|&m| at_least(m, bg, BODY)).unwrap_or(text)
}
