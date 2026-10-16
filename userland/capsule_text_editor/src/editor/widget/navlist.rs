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

//! A vertical label list with one selected row. The selection is a rounded
//! accent cap fading right into transparency, so it must be blended over the
//! paint already on the surface rather than written raw.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::{mix, with_alpha};
use nonos_toolkit::theme::roles;
use nonos_toolkit::ttf::line_height;

use super::truncate::truncate_to_width;
use crate::editor::theme::SELECT_WASH;

pub(in crate::editor) struct NavStyle {
    pub accent: u32,
    pub ring: u32,
    pub label: u32,
    pub label_sel: u32,
    pub radius: u32,
    pub pad_x: u32,
}

impl NavStyle {
    /// The rail list Home and Settings share, in the OS theme's colours: the
    /// selected row washed from the rail towards the accent and edged in it.
    pub(in crate::editor) fn rail(pad_x: u32) -> Self {
        let r = roles();
        Self {
            accent: mix(r.sunken.argb(), r.accent.argb(), SELECT_WASH),
            ring: r.accent_edge.argb(),
            label: r.muted.argb(),
            label_sel: r.text.argb(),
            radius: 9,
            pad_x,
        }
    }
}

pub(in crate::editor) fn nav_row_h(px: f32) -> u32 {
    line_height(px).max(1) as u32 + 10
}

pub(in crate::editor) fn paint_navlist(
    fb: &mut PaintBuffer,
    rect: (u32, u32, u32),
    labels: &[&str],
    selected: usize,
    px: f32,
    st: &NavStyle,
) {
    let (x, y, w) = rect;
    let rh = nav_row_h(px);
    let lh = line_height(px).max(1) as u32;
    let cap = st.radius.saturating_mul(2).min(w);
    for (i, label) in labels.iter().enumerate() {
        let ry = y + i as u32 * rh;
        if i == selected && w > cap {
            let a = st.accent >> 24;
            let mid = with_alpha(st.accent, (a * (w - cap) / w) as u8);
            fb.fill_round(x, ry, cap, rh, st.radius, st.accent);
            fb.gradient_h(x + cap, ry, w - cap, rh, mid, with_alpha(st.accent, 0));
            fb.stroke_round(x, ry, w, rh, st.radius, 1, st.ring);
        }
        let avail = w.saturating_sub(st.pad_x * 2) as i32;
        let cut = truncate_to_width(fb, label, px, avail);
        let color = if i == selected { st.label_sel } else { st.label };
        let ty = (ry + (rh - lh) / 2) as i32;
        let _ = fb.text_ttf((x + st.pad_x) as i32, ty, cut, color, px);
    }
}
