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
use nonos_toolkit::font::ttf::line_height;

use crate::browser::net::mixnet::{self, Network};
use crate::browser::omnibox::geometry::TEXT_PX;
use crate::browser::paint::tokens;
use crate::browser::state::State;
use crate::browser::ui::rect::Rect;

/* The network the next request leaves through, with its badge fill and
 * ink: an anonymising network in teal, the direct one plain. A manual
 * proxy only carries traffic on the direct network, so it is named there. */
pub fn label(state: &State) -> (&'static str, u32, u32) {
    match (mixnet::chosen(), state.proxy.is_some()) {
        (Network::Nym, _) => ("Mixnet", tokens::TEAL_SOFT, tokens::TEAL),
        (Network::Anyone, _) => ("Anyone", tokens::TEAL_SOFT, tokens::TEAL),
        (Network::Direct, true) => ("SOCKS", tokens::FIELD, tokens::MUTED),
        (Network::Direct, false) => ("Direct", tokens::FIELD, tokens::MUTED),
    }
}

/* The route badge at the right end of the address pill. It stays in view
 * so the reader never opens a panel to learn whether the address is hidden. */
pub(super) fn paint(state: &State, r: Rect, fb: &mut PaintBuffer) {
    if r.w <= 0 || r.h <= 0 {
        return;
    }
    let (text, fill, ink) = label(state);
    let (x, y, w, h) = (r.x as u32, r.y as u32, r.w as u32, r.h as u32);
    fb.fill_round(x, y, w, h, h / 2, fill);
    if fill == tokens::FIELD {
        fb.stroke_round(x, y, w, h, h / 2, 1, tokens::EDGE);
    }
    let tw = measure_ttf(text, TEXT_PX);
    let tx = r.x + (r.w - tw).max(0) / 2;
    let ty = r.y + (r.h - line_height(TEXT_PX)) / 2;
    fb.text_ttf(tx, ty, text, ink, TEXT_PX);
}
