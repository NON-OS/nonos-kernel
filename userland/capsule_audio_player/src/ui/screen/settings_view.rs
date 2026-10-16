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

//! The Settings painter. Every fact on this screen is read back from the
//! capsule itself: the directory the library scanned, the count it found, the
//! resampler output rate and the decoders that were compiled in.

extern crate alloc;

use alloc::string::String;
use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::decode::DECODERS;
use crate::library::{Library, Queue};
use crate::model::PlayerView;
use crate::resample::OUT_RATE;
use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{ITEM, LABEL, S2};
use crate::ui::paint::{rule, text_mid, text_right};
use crate::ui::text::push_u32;
use crate::ui::widget::{
    card_panel, page_header, slider, stat_tile, storage_meter, switch, SWITCH_H, SWITCH_W,
};

use super::settings::{
    facts_rect, meter_rect, panel_rect, tiles_rect, toggle_row, volume_rect, FACT_H, TOGGLES,
};

fn num(v: u32) -> String {
    let mut s = String::new();
    push_u32(&mut s, v, 0);
    s
}

fn fact(fb: &mut PaintBuffer, r: Rect, i: i32, key: &str, value: &str) {
    let h = (r.h / 4).min(FACT_H).max(1);
    let row = r.row(i * h, h);
    let t = roles();
    text_mid(fb, row, key, t.muted.argb(), LABEL);
    text_right(fb, row, value, t.text.argb(), ITEM);
    rule(fb, Rect::new(row.x, row.bottom() - 1, row.w, 1));
}

fn playback(fb: &mut PaintBuffer, r: Rect, v: &PlayerView) {
    card_panel(fb, panel_rect(r), "Playback");
    let (states, ink) = ([v.shuffle, v.repeat, v.muted], roles().text.argb());
    for (i, label) in TOGGLES.iter().enumerate() {
        let row = toggle_row(r, i);
        text_mid(fb, row, label, ink, ITEM);
        let sw = Rect::new(row.right() - SWITCH_W, row.cy() - SWITCH_H / 2, SWITCH_W, SWITCH_H);
        switch(fb, sw, states[i]);
        rule(fb, Rect::new(row.x, row.bottom() - 1, row.w, 1));
    }
    let vol = toggle_row(r, 3);
    text_mid(fb, vol, "Volume", ink, ITEM);
    slider(fb, volume_rect(r), v.volume_q15.max(0) as u64, 32768, true);
}

fn counters(fb: &mut PaintBuffer, icons: &Icons, r: Rect, lib: &Library, q: &Queue) {
    let t = tiles_rect(r);
    let queued = q.items().len() as u32;
    let total = lib.tracks.len() as u32;
    let h = (t.h - S2 * 2) / 3;
    let cell = |i: i32| Rect::new(t.x, t.y + i * (h + S2), t.w, h);
    stat_tile(fb, icons, cell(0), &num(total), "Indexed", Glyph::Note);
    stat_tile(fb, icons, cell(1), &num(queued), "Queued", Glyph::Plus);
    stat_tile(fb, icons, cell(2), &num(DECODERS.len() as u32), "Decoders", Glyph::Check);
    let mut label = num(queued);
    label.push_str(" queued");
    storage_meter(fb, meter_rect(r), queued, total.max(1), &label);
}

pub fn paint(
    fb: &mut PaintBuffer,
    icons: &Icons,
    r: Rect,
    v: &PlayerView,
    lib: &Library,
    q: &Queue,
) {
    page_header(fb, r, "Settings", "Playback, and what this player can read.", "");
    playback(fb, r, v);
    let f = card_panel(fb, facts_rect(r), "This capsule");
    fact(fb, f, 0, "Library folder", crate::fetch::name::MUSIC_DIR);
    fact(fb, f, 1, "Tracks found", &num(lib.tracks.len() as u32));
    fact(fb, f, 2, "Output rate", &num(OUT_RATE));
    fact(fb, f, 3, "Decoders", &DECODERS.join(", "));
    counters(fb, icons, r, lib, q);
}
