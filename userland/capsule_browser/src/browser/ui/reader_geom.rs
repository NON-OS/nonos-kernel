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

use super::rect::Rect;

pub const PANEL_W: i32 = 300;
pub const MIN_W: i32 = 200;
pub const MARGIN: i32 = 16;
const PAD: i32 = 20;
const HEAD: i32 = 32;
const LABEL: i32 = 22;
const LABEL_GAP: i32 = 8;
const SECTION: i32 = 20;
const SWATCH_H: i32 = 56;
const CTRL: i32 = 36;
const SEG_GAP: i32 = 8;
const SWITCH_W: i32 = 44;
const SWITCH_H: i32 = 24;

/// Every part of the reader settings card, in content-area coordinates.
/// The painter and the click handler both read this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderGeom {
    pub panel: Rect,
    pub head: Rect,
    pub close: Rect,
    pub labels: [Rect; 3],
    pub swatches: [Rect; 3],
    pub minus: Rect,
    pub plus: Rect,
    pub dots: Rect,
    pub widths: [Rect; 3],
    pub time: Rect,
    pub switch: Rect,
}

/// The card on the right of a `w` wide content area.
pub fn panel(w: i32) -> ReaderGeom {
    let pw = PANEL_W.min(w - 2 * MARGIN).max(0);
    let x = (w - MARGIN - pw).max(0);
    let iw = (pw - 2 * PAD).max(0);
    let ix = x + PAD;
    let mut y = MARGIN + PAD;
    let head = Rect::new(ix, y, iw, HEAD);
    let close = Rect::new(ix + iw - HEAD, y, HEAD, HEAD);
    let label = |y: &mut i32, h: i32| {
        let r = Rect::new(ix, *y, iw, LABEL);
        *y += LABEL + LABEL_GAP + h + SECTION;
        r
    };
    y += HEAD + SECTION;
    let l0 = label(&mut y, SWATCH_H);
    let swatches = Rect::new(ix, l0.bottom() + LABEL_GAP, iw, SWATCH_H).thirds(SEG_GAP);
    let l1 = label(&mut y, CTRL);
    let cy = l1.bottom() + LABEL_GAP;
    let minus = Rect::new(ix, cy, CTRL, CTRL);
    let plus = Rect::new(ix + iw - CTRL, cy, CTRL, CTRL);
    let dots = Rect::new(minus.right(), cy, (plus.x - minus.right()).max(0), CTRL);
    let l2 = label(&mut y, CTRL);
    let widths = Rect::new(ix, l2.bottom() + LABEL_GAP, iw, CTRL).thirds(SEG_GAP);
    let time = Rect::new(ix, y, iw, CTRL);
    let switch = Rect::new(time.right() - SWITCH_W, y + (CTRL - SWITCH_H) / 2, SWITCH_W, SWITCH_H);
    let panel = Rect::new(x, MARGIN, pw, time.bottom() + PAD - MARGIN);
    ReaderGeom {
        panel,
        head,
        close,
        labels: [l0, l1, l2],
        swatches,
        minus,
        plus,
        dots,
        widths,
        time,
        switch,
    }
}
