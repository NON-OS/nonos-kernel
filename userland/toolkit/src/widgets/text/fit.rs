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

//! Cutting a run short at the end with an ellipsis so it fits a width.

use alloc::string::String;
use alloc::vec::Vec;

use crate::paint::measure_ttf;

/// The ellipsis both `truncate` and `tail` mark a cut with, U+2026.
pub(super) const ELLIPSIS: &str = "\u{2026}";

/// `s` unchanged when it measures within `max_w`, otherwise the longest
/// char-aligned prefix that still fits with an ellipsis appended, found by
/// halving. Empty when not even the ellipsis fits.
pub fn truncate_by(s: &str, max_w: i32, measure: impl Fn(&str) -> i32) -> String {
    if measure(s) <= max_w {
        return String::from(s);
    }
    if measure(ELLIPSIS) > max_w {
        return String::new();
    }
    let ends: Vec<usize> = s.char_indices().map(|(i, c)| i + c.len_utf8()).collect();
    let (mut lo, mut hi) = (0usize, ends.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if measure(&[&s[..ends[mid - 1]], ELLIPSIS].concat()) <= max_w {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let cut = if lo == 0 { 0 } else { ends[lo - 1] };
    let mut out = String::from(&s[..cut]);
    out.push_str(ELLIPSIS);
    out
}

/// `truncate_by` measured in the body face at `px`, the face `draw::text`
/// paints with.
pub fn truncate(s: &str, max_w: u32, px: f32) -> String {
    truncate_by(s, i32::try_from(max_w).unwrap_or(i32::MAX), |t| measure_ttf(t, px))
}
