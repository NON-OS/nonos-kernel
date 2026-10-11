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

use alloc::string::String;
use alloc::vec::Vec;

const ELLIPSIS: &str = "\u{2026}";

/// `s` unchanged when it measures within `max_w`, otherwise the longest
/// char-aligned prefix that still fits with an ellipsis appended. Empty when
/// not even the ellipsis fits.
pub fn truncate_to(s: &str, max_w: i32, measure: impl Fn(&str) -> i32) -> String {
    if measure(s) <= max_w {
        return String::from(s);
    }
    let room = max_w - measure(ELLIPSIS);
    if room < 0 {
        return String::new();
    }
    let ends: Vec<usize> = s.char_indices().map(|(i, c)| i + c.len_utf8()).collect();
    let (mut lo, mut hi) = (0usize, ends.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if measure(&s[..ends[mid - 1]]) <= room {
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
