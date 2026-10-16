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

//! The right rail: the cover of what is playing, its scrubber and transport,
//! the volume trim and the up-next queue. `queue_row` is the one geometry
//! source (`rail_geom.rs`), so the hit-test lands on exactly the row the
//! painter drew.

extern crate alloc;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::library::{Library, Queue};
use crate::model::PlayerView;
use crate::transport::State;
use crate::ui::art::cover;
use crate::ui::control::Control;
use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{cap_h, pill, ITEM, LABEL, S1, S2, S3, S4, S5, SECONDARY, SECTION};
use crate::ui::paint::{fill, rule, stroke, text, text_centre, text_mid, text_right};
use crate::ui::text::{mmss, truncate_to_width};
use crate::ui::widget::{permille, slider};

use super::rail_geom::{
    art_rect, body, head_rect, queue_row, queue_visible, seek_rect, transport_row, vol_rect, QROW_H,
};

fn play_rect(r: Rect) -> Rect {
    let tr = transport_row(r);
    Rect::new(tr.cx() - 22, tr.y, 44, 44)
}

// The four small buttons beside play, in the order prev, next, shuffle, repeat.
fn small_rects(r: Rect) -> [Rect; 4] {
    let b = body(r);
    let tr = transport_row(r);
    let big = play_rect(r);
    [
        Rect::new(big.x - 44 - S3, tr.y + 7, 30, 30),
        Rect::new(big.right() + S3, tr.y + 7, 30, 30),
        Rect::new(b.x, tr.y + 7, 30, 30),
        Rect::new(b.right() - 30, tr.y + 7, 30, 30),
    ]
}

fn speaker_rect(r: Rect) -> Rect {
    let b = body(r);
    Rect::new(b.x, vol_rect(r).cy() - 11, 22, 22)
}

/// The rail's own transport answers clicks the same way the bar's does.
pub fn control_at(r: Rect, x: i32, y: i32) -> Option<Control> {
    if play_rect(r).contains(x, y) {
        return Some(Control::PlayPause);
    }
    let small = [Control::Prev, Control::Next, Control::Shuffle, Control::Repeat];
    if let Some(i) = (0..4).find(|&i| small_rects(r)[i].contains(x, y)) {
        return Some(small[i]);
    }
    if speaker_rect(r).contains(x, y) {
        return Some(Control::Mute);
    }
    let seek = seek_rect(r);
    if seek.inset(-8).contains(x, y) {
        return Some(Control::Seek(permille(seek, x)));
    }
    let vol = vol_rect(r);
    if vol.inset(-8).contains(x, y) {
        return Some(Control::Volume(permille(vol, x)));
    }
    None
}

fn round_btn(fb: &mut PaintBuffer, icons: &Icons, r: Rect, g: Glyph, ink: u32) {
    icons.centred(fb, r, 18, g, ink);
}

pub fn rail(
    fb: &mut PaintBuffer,
    icons: &Icons,
    r: Rect,
    lib: &Library,
    queue: &Queue,
    view: &PlayerView,
) {
    if r.w <= 0 {
        return;
    }
    let th = roles();
    let (ink, muted) = (th.text.argb(), th.muted.argb());
    fill(fb, r, 0, th.surface.argb());
    fill(fb, Rect::new(r.x, r.y, 1, r.h), 0, th.border.argb());

    let b = body(r);
    let art = art_rect(r);
    let title = view.title.as_str();
    let artist = view.artist.as_str();
    cover(fb, art, title, 12);

    let ty = art.bottom() + S5;
    let head = truncate_to_width(title, SECTION, b.w);
    text(fb, b.x, ty, &head, ink, SECTION);
    let sub = truncate_to_width(artist, SECONDARY, b.w);
    text(fb, b.x, ty + cap_h(SECTION) * 2, &sub, th.text_2.argb(), SECONDARY);

    let seek = seek_rect(r);
    slider(fb, seek, view.pos_ms as u64, view.dur_ms.max(1) as u64, true);
    let times = Rect::new(b.x, seek.bottom() + S2, b.w, cap_h(LABEL) * 2);
    text_mid(fb, times, &mmss(view.pos_ms), muted, LABEL);
    text_right(fb, times, &mmss(view.dur_ms), muted, LABEL);

    let big = play_rect(r);
    fill(fb, big, pill(44), th.accent.argb());
    let g = if view.state == State::Playing { Glyph::Pause } else { Glyph::Play };
    icons.centred(fb, big, 19, g, th.on_accent.argb());
    let [prev, next, shuffle, repeat] = small_rects(r);
    round_btn(fb, icons, prev, Glyph::Prev, ink);
    round_btn(fb, icons, next, Glyph::Next, ink);
    let sh = if view.shuffle { th.accent.argb() } else { muted };
    let rp = if view.repeat { th.accent.argb() } else { muted };
    round_btn(fb, icons, shuffle, Glyph::Shuffle, sh);
    round_btn(fb, icons, repeat, Glyph::Repeat, rp);

    let vol = vol_rect(r);
    let spk = if view.muted { th.danger } else { th.text_2 }.argb();
    icons.centred(fb, speaker_rect(r), 16, Glyph::Speaker, spk);
    let level = if view.muted { 0 } else { view.volume_q15.max(0) as u64 };
    slider(fb, vol, level, 32768, false);

    let qh = head_rect(r);
    text_mid(fb, qh, "Up next", ink, SECONDARY);
    rule(fb, Rect::new(b.x, qh.bottom() - 1, b.w, 1));

    let items = queue.items();
    let shown = queue_visible(r).min(items.len());
    for i in 0..shown {
        let row = queue_row(r, i);
        let Some(t) = lib.get(items[i]) else { continue };
        if lib.get(items[i]).is_some_and(|t| t.title == view.title) {
            fill(fb, row, 8, th.accent_wash.argb());
            stroke(fb, row, 8, 1, th.accent_edge.argb());
        }
        let thumb = Rect::new(row.x + S2, row.cy() - 16, 32, 32);
        cover(fb, thumb, &t.title, 7);
        let tx = thumb.right() + S3;
        let tw = row.right() - S3 - tx;
        text(
            fb,
            tx,
            row.cy() - cap_h(SECONDARY) - S1,
            &truncate_to_width(&t.title, SECONDARY, tw),
            ink,
            SECONDARY,
        );
        text(fb, tx, row.cy() + S1, &truncate_to_width(&t.artist, LABEL, tw), muted, LABEL);
    }
    if shown == 0 {
        let empty = Rect::new(b.x, queue_row(r, 0).y, b.w, QROW_H);
        text_centre(fb, empty, "Queue is empty", th.quiet.argb(), ITEM);
    }
    let _ = (S1, S4);
}
