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

//! The source tabs: each tab's highlight, selected or hovered, is the very
//! rectangle a click on it answers in.

use nonos_toolkit::paint::PaintBuffer;

use crate::store::tab::{Tab, TABS};
use crate::store::ui::metrics::WIN_W;
use crate::store::ui::tab_strip::{band, draw};
use crate::store::ui::target::Target;
use crate::store_hover_tests::{at, window};

/// A box by its first and last column and row, inclusive.
type Span = (u32, u32, u32, u32);

const H: u32 = 120;

fn bounds(points: impl Iterator<Item = (u32, u32)>) -> Option<Span> {
    points.fold(None, |b, (x, y)| match b {
        None => Some((x, x, y, y)),
        Some((x0, x1, y0, y1)) => Some((x0.min(x), x1.max(x), y0.min(y), y1.max(y))),
    })
}

fn strip(on: Option<Tab>, hovered: Option<usize>) -> Vec<u32> {
    let mut px = vec![0; (WIN_W * H) as usize];
    let mut fb = PaintBuffer { pixels: &mut px, stride_words: WIN_W, width: WIN_W, height: H };
    draw(&mut fb, WIN_W, on, hovered);
    px
}

fn lit(a: &[u32], b: &[u32]) -> Option<Span> {
    let pairs = a.iter().zip(b).enumerate().filter(|(_, (p, q))| p != q);
    bounds(pairs.map(|(i, _)| (i as u32 % WIN_W, i as u32 / WIN_W)))
}

/// Where a click names tab `i`, which must fill the box it spans.
pub(crate) fn hit(i: usize) -> Span {
    let state = window(0);
    let all = (0..H).flat_map(|y| (0..WIN_W).map(move |x| (x, y)));
    let on: Vec<_> = all.filter(|&(x, y)| at(&state, x, y) == Target::Tab(i)).collect();
    let b = bounds(on.iter().copied()).unwrap();
    assert_eq!(on.len() as u32, (b.1 - b.0 + 1) * (b.3 - b.2 + 1), "tab {i}");
    b
}

#[test]
fn each_tabs_highlight_is_its_hit_box() {
    let none = strip(None, None);
    for i in 0..TABS.len() {
        let (b, other) = (Some(hit(i)), Some(TABS[(i + 1) % TABS.len()]));
        assert_eq!(lit(&strip(Some(TABS[i]), None), &none), b, "selected {i}");
        assert_eq!(lit(&strip(other, Some(i)), &strip(other, None)), b, "hovered {i}");
    }
    let (b, band) = (hit(0), band(WIN_W));
    assert!(b.2 >= band.y && b.3 < band.y + band.h);
}
