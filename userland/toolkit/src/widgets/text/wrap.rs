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

//! Breaking a run into lines at whitespace so each fits a width.

use alloc::vec::Vec;

use crate::paint::measure_ttf;

/// Byte ranges of `text` broken into lines no wider than `max_w`, breaking
/// at whitespace. A word wider than `max_w` takes a line of its own. Line
/// width is the sum of its words and the spaces between them.
pub fn wrap_by(text: &str, max_w: i32, measure: impl Fn(&str) -> i32) -> Vec<(usize, usize)> {
    let space = measure(" ");
    let mut lines = Vec::new();
    let mut line: Option<(usize, usize, i32)> = None;
    for (start, end) in words(text) {
        let w = measure(&text[start..end]);
        line = match line {
            Some((s, _, lw)) if lw.saturating_add(space).saturating_add(w) <= max_w => {
                Some((s, end, lw.saturating_add(space).saturating_add(w)))
            }
            Some((s, e, _)) => {
                lines.push((s, e));
                Some((start, end, w))
            }
            None => Some((start, end, w)),
        };
    }
    lines.extend(line.map(|(s, e, _)| (s, e)));
    lines
}

/// `wrap_by` measured in the body face at `px`, the face `draw::text` paints
/// with.
pub fn wrap(text: &str, max_w: u32, px: f32) -> Vec<(usize, usize)> {
    wrap_by(text, i32::try_from(max_w).unwrap_or(i32::MAX), |t| measure_ttf(t, px))
}

/// Byte ranges of the whitespace-separated words of `text`, in order.
fn words(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut start: Option<usize> = None;
    let mut chars = text.char_indices().chain(core::iter::once((text.len(), ' ')));
    core::iter::from_fn(move || {
        for (i, c) in chars.by_ref() {
            match (c.is_whitespace(), start) {
                (true, Some(s)) => {
                    start = None;
                    return Some((s, i));
                }
                (false, None) => start = Some(i),
                _ => {}
            }
        }
        None
    })
}
