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

//! Track table: the column solver, the header rule and one row.

extern crate alloc;

use alloc::string::String;
use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::library::Track;
use crate::ui::art::cover;
use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{line_h, DATA, ITEM, LABEL, R_THUMB, S3, S4, SECONDARY};
use crate::ui::paint::{fill, rule, text, text_mid, text_right};
use crate::ui::text::{mmss, push_u32, truncate_to_width, upper};

use super::eq::equalizer;

pub const ROW_H: i32 = 54;

pub struct Cols {
    pub index: Rect,
    pub art: Rect,
    pub title: Rect,
    pub format: Rect,
    pub time: Rect,
    pub pip: Rect,
}

pub fn cols(r: Rect) -> Cols {
    let art_s = ROW_H - S4;
    let ix = Rect::new(r.x + S3, r.y, 34, r.h);
    let art = Rect::new(ix.right() + S3, r.cy() - art_s / 2, art_s, art_s);
    let pip = Rect::new(r.right() - 34, r.y, 26, r.h);
    let time = Rect::new(pip.x - 80, r.y, 70, r.h);
    /* Room for an album's name; the title keeps the rest. */
    let format = Rect::new(time.x - 236, r.y, 220, r.h);
    Cols { index: ix, art, title: Rect::new(art.right() + S4, r.y, format.x - art.right() - S4 * 2, r.h), format, time, pip }
}

pub fn header(fb: &mut PaintBuffer, r: Rect) {
    let (c, muted) = (cols(r), roles().muted.argb());
    text_mid(fb, c.index, "#", muted, LABEL);
    text_mid(fb, c.title, &upper("Title"), muted, LABEL);
    text_mid(fb, c.format, &upper("Album"), muted, LABEL);
    text_right(fb, c.time, &upper("Time"), muted, LABEL);
    rule(fb, Rect::new(r.x, r.bottom() - 1, r.w, 1));
}

pub struct Flags {
    pub playing: bool,
    pub queued: bool,
    pub hover: bool,
}

pub fn row(fb: &mut PaintBuffer, icons: &Icons, r: Rect, t: &Track, n: usize, f: &Flags, level: u16) {
    let (playing, queued) = (f.playing, f.queued);
    let (c, th) = (cols(r), roles());
    let text_2 = th.text_2.argb();
    if f.hover && !playing {
        fill(fb, r, 8, th.hover_wash.argb());
    }
    if playing {
        fill(fb, r, 8, th.hover_wash.argb());
        equalizer(fb, c.index.centred(16, 16), level);
    } else {
        let mut s = String::new();
        push_u32(&mut s, n as u32, 2);
        text_mid(fb, c.index, &s, th.muted.argb(), DATA);
    }
    cover(fb, c.art, &t.path, R_THUMB as u32);
    let fg = if playing { th.accent } else { th.text }.argb();
    let ty = r.cy() - (line_h(ITEM) + line_h(SECONDARY)) / 2;
    let title = truncate_to_width(&t.title, ITEM, c.title.w);
    text(fb, c.title.x, ty, &title, fg, ITEM);
    let artist = truncate_to_width(&t.artist, SECONDARY, c.title.w);
    text(fb, c.title.x, ty + line_h(ITEM), &artist, text_2, SECONDARY);
    /* The album its tags name, or the file's format when they name none. */
    let album = if t.album.is_empty() { t.format.clone() } else { truncate_to_width(&t.album, DATA, c.format.w) };
    text_mid(fb, c.format, &album, text_2, DATA);
    /* A track not loaded yet has no known length: "--", not "0:00". */
    let time = if t.dur_ms == 0 { String::from("--") } else { mmss(t.dur_ms) };
    text_right(fb, c.time, &time, text_2, DATA);
    if queued {
        icons.centred(fb, c.pip, 18, Glyph::Check, th.ok.argb());
    }
}
