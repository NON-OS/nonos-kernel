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

//! Where the pane sits in the window and where Overview's table sits in the
//! pane: plain boxes the painters draw into and the hit test reads, kept
//! apart from the painting so the proofs can mount them.

use nonos_toolkit::widgets::Rect;

use super::fit::sidebar_w;
use super::metrics::{CARD_GAP, CARD_H, HEAD_H, INSPECTOR_W, PANE_PAD_TOP, PANE_PAD_X, STATUS_H};

// The content box for the active screen: everything right of the sidebar, below
// the page head, above the status bar, and left of the inspector when one is
// docked. Every screen painter takes this rect and never recomputes it.
pub fn pane_rect(fb_w: u32, fb_h: u32, inspector: bool) -> Rect {
    let right = if inspector { fb_w.saturating_sub(INSPECTOR_W) } else { fb_w };
    let side = sidebar_w(fb_w);
    Rect {
        x: side + PANE_PAD_X,
        y: PANE_PAD_TOP + HEAD_H,
        w: right.saturating_sub(side + PANE_PAD_X * 2),
        h: fb_h.saturating_sub(PANE_PAD_TOP + HEAD_H + STATUS_H + PANE_PAD_X),
    }
}

/* The table sits under the cards. The hit test and the row budget read this
 * same rect, so a click lands on the row drawn under the pointer. */
pub fn table_rect(r: &Rect) -> Rect {
    let below = CARD_H + CARD_GAP;
    Rect { x: r.x, y: r.y + below, w: r.w, h: r.h.saturating_sub(below) }
}
