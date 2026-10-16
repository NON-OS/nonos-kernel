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

//! Downloads: every MP3 link the person asked for, newest last, each with
//! how far it has got and what can be done with it: cancel one running or
//! waiting, resume one the network stopped, play one that is in, remove a
//! finished one. With none, the page says how to add music.

extern crate alloc;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use crate::fetch::list::{Act, Row, State};
use crate::fetch::row_text::{label, permille, status};
use crate::ui::geometry::Rect;
use crate::ui::icon::{Glyph, Icons};
use crate::ui::metrics::{line_h, BODY, ITEM, PAGE, S3, S4, S6, SECONDARY};
use crate::ui::paint::{card, fill, text, text_mid};
use crate::ui::text::{count, truncate_to_width};
use crate::ui::widget::{button, button_w, page_header, slider, Variant};

const CLEAR: &str = "Clear finished";
const ROW_H: i32 = 84;
const BTN_H: i32 = 36;

fn list_top(r: Rect) -> i32 {
    r.y + line_h(PAGE) + line_h(SECONDARY) + S6
}

/// Rows the page has room for.
pub fn visible(r: Rect) -> usize {
    ((r.bottom() - list_top(r)).max(0) / (ROW_H + S3)) as usize
}

fn row_rect(r: Rect, slot: usize) -> Rect {
    Rect::new(r.x, list_top(r) + slot as i32 * (ROW_H + S3), r.w, ROW_H)
}

pub fn clear_rect(r: Rect) -> Rect {
    let w = button_w(CLEAR, false);
    Rect::new(r.right() - w, r.y + (line_h(PAGE) - 38) / 2, w, 38)
}

/// The buttons of the row in `rr`, right to left in the order `acts` gives
/// them, so the likeliest sits at the edge.
fn buttons(rr: Rect, acts: &[Act]) -> impl Iterator<Item = (Act, Rect)> + '_ {
    let mut right = rr.right() - S4;
    acts.iter().map(move |&a| {
        let w = button_w(label(a), false);
        right -= w;
        let b = Rect::new(right, rr.cy() - BTN_H / 2, w, BTN_H);
        right -= S3;
        (a, b)
    })
}

/// What a click at (x, y) asks of which row.
pub fn act_at(r: Rect, rows: &[Row], scroll: usize, x: i32, y: i32) -> Option<(u32, Act)> {
    for slot in 0..visible(r) {
        let Some(row) = rows.get(scroll + slot) else { break };
        let rr = row_rect(r, slot);
        if !rr.contains(x, y) {
            continue;
        }
        return buttons(rr, row.acts()).find(|(_, b)| b.contains(x, y)).map(|(a, _)| (row.id, a));
    }
    None
}

/// Whether the page offers Clear finished.
pub fn any_finished(rows: &[Row]) -> bool {
    rows.iter().any(|r| !matches!(r.state, State::Queued | State::Running | State::Stopping))
}

pub fn paint(fb: &mut PaintBuffer, icons: &Icons, r: Rect, rows: &[Row], scroll: usize) {
    let running = rows.iter().filter(|r| matches!(r.state, State::Running | State::Queued)).count();
    let sub = if rows.is_empty() {
        alloc::string::String::from("MP3 links you paste into Search download here, over the network you chose.")
    } else if running > 0 {
        count(running, "download in progress", "downloads in progress")
    } else {
        alloc::string::String::from("All done. Finished downloads are in /home/nonos/music.")
    };
    page_header(fb, r, "Downloads", &sub, "");
    if any_finished(rows) {
        button(fb, icons, clear_rect(r), CLEAR, None, Variant::Ghost);
    }
    if rows.is_empty() {
        empty(fb, icons, r);
        return;
    }
    for slot in 0..visible(r) {
        let Some(row) = rows.get(scroll + slot) else { break };
        one(fb, icons, row_rect(r, slot), row);
    }
}

fn one(fb: &mut PaintBuffer, icons: &Icons, rr: Rect, row: &Row) {
    let t = roles();
    card(fb, rr);
    let (glyph, tint) = match row.state {
        State::Done(_) => (Glyph::Check, t.ok),
        State::Failed { resumable: false, .. } => (Glyph::Close, t.danger),
        _ => (Glyph::Download, t.accent),
    };
    let badge = Rect::new(rr.x + S4, rr.cy() - 22, 44, 44);
    fill(fb, badge, 12, with_alpha(tint.argb(), 0x22));
    icons.centred(fb, badge, 22, glyph, tint.argb());

    let acts = row.acts();
    let left_of_buttons = buttons(rr, acts).last().map_or(rr.right() - S4, |(_, b)| b.x - S4);
    let tx = badge.right() + S4;
    let tw = (left_of_buttons - tx).max(0);
    let top = rr.y + S4;
    text(fb, tx, top, &truncate_to_width(&row.name, ITEM, tw), t.text.argb(), ITEM);
    let said = status(row);
    let ink = match row.state {
        State::Failed { .. } => t.danger,
        State::Done(_) => t.ok,
        _ => t.text_2,
    };
    let line = truncate_to_width(&said, SECONDARY, tw);
    text(fb, tx, top + line_h(ITEM) + 2, &line, ink.argb(), SECONDARY);
    if matches!(row.state, State::Running | State::Stopping) {
        let bar = Rect::new(tx, rr.bottom() - S4 - 6, tw, 8);
        match permille(row) {
            Some(p) => slider(fb, bar, u64::from(p), 1000, false),
            None => slider(fb, bar, 0, 1, false),
        }
    }
    for (a, b) in buttons(rr, acts) {
        let v = if a == Act::Play || a == Act::Resume { Variant::Glow } else { Variant::Ghost };
        button(fb, icons, b, label(a), None, v);
    }
}

/// No downloads yet: how music gets here.
fn empty(fb: &mut PaintBuffer, icons: &Icons, r: Rect) {
    let (body, t) = (Rect::new(r.x, list_top(r), r.w.min(760), 220), roles());
    card(fb, body);
    let badge = Rect::new(body.x + S6, body.y + S6, 56, 56);
    fill(fb, badge, 14, with_alpha(t.accent.argb(), 0x22));
    icons.centred(fb, badge, 28, Glyph::Download, t.accent.argb());
    let tx = badge.right() + S6;
    let tw = body.right() - S6 - tx;
    let mut y = body.y + S6;
    text(fb, tx, y, "Bring your own music", t.text.argb(), ITEM);
    y += line_h(ITEM) + S3;
    let lines = [
        "1.  Copy the link to an MP3 file.",
        "2.  Press / or click Search, then Ctrl+V and Enter.",
        "3.  It downloads over Anyone or Nym into /home/nonos/music and plays.",
        "Files you copy into /home/nonos/music appear in the Library too.",
    ];
    for l in lines {
        let line = truncate_to_width(l, BODY, tw);
        text_mid(fb, Rect::new(tx, y, tw, line_h(BODY)), &line, t.text_2.argb(), BODY);
        y += line_h(BODY) + S3 / 2;
    }
}
