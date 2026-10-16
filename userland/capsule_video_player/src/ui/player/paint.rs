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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::transport::{transport, Transport, HEX_R};
use crate::ui::chrome::BarState;
use crate::ui::icon;
use crate::ui::layout::{Layout, Rect};
use crate::ui::paint::shape;
use crate::ui::text::{center_y, hhmmss, BODY_PX};
use crate::ui::widget::progress::paint_scrub;

const GLYPH: u32 = 18;
const NO_SOUND: &str = "Picture only, no sound";

fn center(r: Rect, size: u32) -> (u32, u32) {
    (r.x + r.w.saturating_sub(size) / 2, r.y + r.h.saturating_sub(size) / 2)
}

fn paint_play(fb: &mut PaintBuffer, t: &Transport, playing: bool) {
    let cx = t.play.x + HEX_R;
    let cy = t.play.y + HEX_R;
    let theme = roles();
    shape::hex(fb, cx, cy, HEX_R, theme.accent.argb());
    let (gx, gy) = center(t.play, GLYPH);
    let ink = theme.on_accent.argb();
    if playing {
        icon::transport::pause(fb, gx, gy, GLYPH, ink);
    } else {
        icon::transport::play(fb, gx, gy, GLYPH, ink);
    }
}

fn paint_sides(fb: &mut PaintBuffer, t: &Transport) {
    let (px, py) = center(t.prev, GLYPH);
    let theme = roles();
    icon::transport::prev(fb, px, py, GLYPH, theme.text.argb());
    let (nx, ny) = center(t.next, GLYPH);
    icon::transport::next(fb, nx, ny, GLYPH, theme.text.argb());
    /* Said in place of a volume control: the stream has no sound to set. */
    let w = fb.measure_ttf(NO_SOUND, BODY_PX).max(0) as u32;
    if w <= t.note.w {
        let x = t.note.x + t.note.w - w;
        let y = center_y(t.note.y, t.note.h);
        fb.text_ttf(x as i32, y, NO_SOUND, theme.muted.argb(), BODY_PX);
    }
}

fn paint_times(fb: &mut PaintBuffer, l: &Layout, st: &BarState) {
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    let (y, theme) = (center_y(l.scrub.y + 14, 20), roles());
    fb.text_ttf(l.elapsed_x as i32, y, hhmmss(st.elapsed_ms, &mut a), theme.text.argb(), BODY_PX);
    let total = hhmmss(st.total_ms, &mut b);
    let w = fb.measure_ttf(total, BODY_PX).max(0) as u32;
    fb.text_ttf(l.remain_x.saturating_sub(w) as i32, y, total, theme.text_2.argb(), BODY_PX);
}

pub fn paint_transport(fb: &mut PaintBuffer, l: &Layout, st: &BarState) {
    fb.fill_rect(l.bar.x, l.bar.y, l.bar.w, l.bar.h, roles().surface.argb());
    paint_scrub(fb, l.scrub, st.permille, st.permille);
    paint_times(fb, l, st);
    let t = transport(l, fb.width);
    paint_play(fb, &t, st.playing);
    paint_sides(fb, &t);
}
