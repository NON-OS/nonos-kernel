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

//! Dialog: where the row has room, each button is drawn at its own size, in
//! order, `SPACE.sm` apart, the last `SPACE.xl` in from the panel's right
//! and bottom edges. Buttons too wide for the row share it equally and stay
//! inside the panel's padding.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::SPACE;
use nonos_toolkit::widgets::rect::inset;
use nonos_toolkit::widgets::{Button, Dialog, Rect};

use super::boxes::{boxes, within};
use super::canvas::Canvas;
use super::dialog::{Buttons, BODIES, SETS};
use super::serial::{serial, SCALES};

/// The smallest rect holding every pixel that lighting button `i` changes.
pub(crate) fn drawn(d: Dialog, i: usize, at: Rect) -> Option<Rect> {
    let paint = |d: Dialog| Canvas::new(at, 0).painted(|fb| d.draw(fb, at));
    let all = paint(d.hovered(Some(i)).pressed(Some(i)).focus(i)).diff(&paint(d));
    let (xs, ys) = (all.iter().map(|p| p.0), all.iter().map(|p| p.1));
    let (x0, x1, y0, y1) = (xs.clone().min()?, xs.max()?, ys.clone().min()?, ys.max()?);
    Some(Rect { x: x0, y: y0, w: x1 - x0 + 1, h: y1 - y0 + 1 })
}

/// A line when the rects drawn for the buttons of `set` in `at` are not
/// laid out as the row lays them out, or one of them is not drawn.
fn misplaced(d: Dialog, set: Buttons, at: Rect) -> Option<String> {
    let s = scale();
    let (sm, p) = (s.px(u32::from(SPACE.sm)), d.panel(at));
    let inner = inset(Rect { h: p.h - s.hair() * 2, ..p }, s.px(u32::from(SPACE.xl)));
    let rects: Vec<Rect> = (0..set.len()).filter_map(|i| drawn(d, i, at)).collect();
    let own = set.iter().map(|&(l, k)| Button::new(l).kind(k).size());
    let fits = own.clone().map(|o| o.0 + sm).sum::<u32>() - sm <= inner.w;
    let sized = rects.iter().zip(own).all(|(r, o)| !fits || (r.w, r.h) == o);
    let shared = fits || rects.iter().all(|r| r.w == rects[0].w);
    let gaps = rects.windows(2).all(|w| !fits || w[1].x == w[0].x + w[0].w + sm);
    let end = rects.last().map(|r| (r.x + r.w, r.y + r.h));
    let edge = !fits || end == Some((inner.x + inner.w, inner.y + inner.h));
    let inside = rects.len() == set.len() && rects.iter().all(|r| within(*r, inner));
    let ok = sized && shared && gaps && edge && inside;
    (!ok).then(|| format!("drawn {rects:?} in {inner:?}"))
}

#[test]
fn dialog_buttons_sit_at_their_own_size_right_aligned_in_the_row() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for set in SETS.into_iter().skip(1) {
            let d = Dialog::new("Delete?").body(BODIES[0]).buttons(set);
            for at in &boxes(d.size())[..2] {
                fails.extend(misplaced(d, set, *at).map(|e| format!("{set:?} at {q}/4: {e}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
