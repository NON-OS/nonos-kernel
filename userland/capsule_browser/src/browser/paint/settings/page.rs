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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::font::ttf::line_height;

use super::{controls, lines};
use crate::browser::paint::pages::extent::page_scroll;
use crate::browser::paint::pages::group_head::TITLE_PX;
use crate::browser::paint::{clip, tokens::palette};
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::settings_geom::{Kind, SettingsGeom, BAND_H};

pub const PX: f32 = 17.0;
const HEAD_PX: f32 = 20.0;
const RADIUS: u32 = 14;
const SPREAD: u32 = 4;
const SUB: &str = "Choices here hold for every tab in this window";

/// The settings page, into a buffer the size of the content area: its
/// sections at their scroll, then the header band over them.
pub fn paint(state: &State, shell: &Shell, fb: &mut PaintBuffer) {
    fb.fill_rect(0, 0, fb.width, fb.height, palette().ground);
    let (w, h) = (fb.width as i32, fb.height as i32);
    let g = SettingsGeom::new(w, h, page_scroll(shell, w, h));
    for it in g.items.iter() {
        let r = it.rect;
        match it.kind {
            Kind::Card => clip::panel(fb, r, RADIUS, SPREAD, palette().surface, palette().edge),
            _ if r.y < 0 || r.y >= h => {}
            Kind::Head(s) => text(fb, r, s, palette().ink, HEAD_PX),
            Kind::Label(s) => text(fb, r, s, palette().ink2, PX),
            Kind::Ctl(c) => controls::paint(fb, state, shell, c, r),
            Kind::Line(l) => lines::paint(fb, state, shell, l, r),
        }
    }
    fb.fill_rect(0, 0, fb.width, BAND_H.min(h).max(0) as u32, palette().ground);
    fb.text_ttf(g.frame.x, g.title_y, "Settings", palette().ink, TITLE_PX);
    fb.text_ttf(g.frame.x, g.sub_y, SUB, palette().muted, PX);
}

/// `s` at the left of `r`, centred on its height.
pub fn text(fb: &mut PaintBuffer, r: Rect, s: &str, argb: u32, px: f32) {
    fb.text_ttf(r.x, r.y + (r.h - line_height(px)) / 2, s, argb, px);
}
