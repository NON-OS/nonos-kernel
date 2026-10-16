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

//! The tray: the labels apps have registered (OP_TRAY_REGISTER), drawn on the
//! menu bar between the menu titles and the status cluster, in the order the
//! tray table holds them. When they do not all fit, the first that do are
//! drawn and a "+N" says how many are not (`state::tray::fit`). A label is
//! status text, not a control: nothing here is hit-tested.

use alloc::vec::Vec;

use super::metrics::gap;
use crate::render::layout::menubar_rect;
use crate::render::measure_aa::measure_aa_bytes;
use crate::render::menubar_menu::titles_right;
use crate::render::text_aa::text_aa_bytes;
use crate::render::ui_font::{top_y_centered, valid_str, STATUS_PX};
use crate::state::tray::fit::{fit, span};
use crate::state::Context;

/// Draw the tray's labels ending a gap left of `right`, the status cluster.
pub(super) fn tray(ctx: &Context, right: u32) {
    let labels: Vec<&str> = ctx.tray.labels().map(valid_str).collect();
    if labels.is_empty() {
        return;
    }
    let left = titles_right(ctx) + gap();
    let Some(room) = right.checked_sub(left + gap()) else {
        return;
    };
    let widths: Vec<u32> =
        labels.iter().map(|l| measure_aa_bytes(l.as_bytes(), STATUS_PX)).collect();
    let mut most = [0u8; 12];
    let most = more_mark(labels.len(), &mut most);
    let shown = fit(&widths, room, gap(), measure_aa_bytes(most, STATUS_PX));
    let hidden = labels.len() - shown;
    let mut mark = [0u8; 12];
    let mark = if hidden > 0 { more_mark(hidden, &mut mark) } else { &[][..] };
    let mut used = span(&widths[..shown], gap());
    if !mark.is_empty() {
        used += measure_aa_bytes(mark, STATUS_PX) + if shown > 0 { gap() } else { 0 };
    }
    let bar = menubar_rect(ctx.width);
    let y = top_y_centered(bar.y, bar.height, STATUS_PX);
    let mut x = right.saturating_sub(gap() + used);
    for (label, w) in labels.iter().zip(&widths).take(shown) {
        text_aa_bytes(ctx, x, y, label.as_bytes(), ctx.palette.text_dim, STATUS_PX);
        x += w + gap();
    }
    if !mark.is_empty() {
        text_aa_bytes(ctx, x, y, mark, ctx.palette.text_dim, STATUS_PX);
    }
}

/// "+N", the count of labels left out.
fn more_mark(n: usize, buf: &mut [u8; 12]) -> &[u8] {
    buf[0] = b'+';
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    let mut v = n;
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let d = digits.len() - i;
    buf[1..1 + d].copy_from_slice(&digits[i..]);
    &buf[..1 + d]
}
