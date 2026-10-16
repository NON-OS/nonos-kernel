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

//! Keeping the end of a run, behind an ellipsis, so it fits a width.

use alloc::string::String;
use alloc::vec::Vec;

use super::fit::ELLIPSIS;
use crate::paint::measure_ttf;

/// `s` unchanged when it measures within `max_w`, otherwise an ellipsis
/// followed by the longest char-aligned end of `s` that still fits: for a
/// field whose text runs on past its width, where the newest characters are
/// the ones to see. Empty when not even the ellipsis fits. The end is found by
/// halving, since an address runs to a thousand characters and measuring
/// every end of it on each paint would cost a million glyph lookups.
pub fn tail_by(s: &str, max_w: i32, measure: impl Fn(&str) -> i32) -> String {
    if measure(s) <= max_w {
        return String::from(s);
    }
    if measure(ELLIPSIS) > max_w {
        return String::new();
    }
    let starts: Vec<usize> = s.char_indices().map(|(i, _)| i).collect();
    let (mut lo, mut hi) = (0usize, starts.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        if measure(&[ELLIPSIS, &s[starts[mid]..]].concat()) <= max_w {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    let from = starts.get(lo).copied().unwrap_or(s.len());
    let mut out = String::from(ELLIPSIS);
    out.push_str(&s[from..]);
    out
}

/// `tail_by` measured in the body face at `px`, the face `draw::text` paints
/// with.
pub fn tail(s: &str, max_w: u32, px: f32) -> String {
    tail_by(s, i32::try_from(max_w).unwrap_or(i32::MAX), |t| measure_ttf(t, px))
}
