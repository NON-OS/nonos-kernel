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

use alloc::format;
use alloc::string::String;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};

use crate::browser::net::mixnet::{self, Network};
use crate::browser::paint::{clip, tokens::palette};
use crate::browser::state::State;
use crate::browser::ui::fit;
use crate::browser::ui::rect::Rect;

const RADIUS: u32 = 14;
const SPREAD: u32 = 4;
const TITLE_PX: f32 = 18.0;
const COUNT_W: i32 = 40;
pub(super) const PAD: i32 = 18;
pub(super) const LINE_PX: f32 = 17.0;
pub(super) const FIRST: i32 = 52;
pub(super) const STEP: i32 = 28;

/// Where the network the next request takes leads.
pub(super) fn endpoint(state: &State) -> String {
    match (mixnet::chosen(), state.proxy.as_ref()) {
        (Network::Nym, _) => String::from("Through the Nym mixnet"),
        (Network::Anyone, _) => String::from("Through the Anyone network"),
        (Network::Direct, Some(p)) => format!("SOCKS5 proxy {}:{}", p.host, p.port),
        (Network::Direct, None) => String::from("Not anonymised"),
    }
}

/// A card's panel and title.
pub(super) fn card(fb: &mut PaintBuffer, r: Rect, title: &str) {
    clip::panel(fb, r, RADIUS, SPREAD, palette().surface, palette().edge);
    fb.text_ttf(r.x + PAD, r.y + PAD, title, palette().ink, TITLE_PX);
}

/// Line `i` of a card, cut to the room left of its count column.
pub(super) fn line(fb: &mut PaintBuffer, r: Rect, i: usize, s: &str, argb: u32) {
    let shown = fit::truncate_to(s, r.w - 2 * PAD - COUNT_W, |t| measure_ttf(t, LINE_PX));
    fb.text_ttf(r.x + PAD, r.y + FIRST + i as i32 * STEP, &shown, argb, LINE_PX);
}
