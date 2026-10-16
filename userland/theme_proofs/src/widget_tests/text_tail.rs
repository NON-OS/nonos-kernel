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

//! `tail`: the run unchanged when it fits; otherwise `…` and the longest end
//! cut on a char boundary that fits, or nothing.

use nonos_toolkit::widgets::text::{tail, tail_by, width};

use super::samples::{sizes, tens, RUNS};
use super::serial::serial;

/// What is wrong with `out` as `tail(s, max_w, px)`, if anything.
fn fault(s: &str, max_w: u32, px: f32, out: &str) -> Option<String> {
    let w = width(out, px);
    if w > max_w {
        return Some(format!("{out:?} is {w} wide, over {max_w}"));
    }
    if width(s, px) <= max_w {
        return (out != s).then(|| format!("{out:?} changed a run that fits"));
    }
    let Some(end) = out.strip_prefix('…') else {
        return (!out.is_empty() || width("…", px) <= max_w).then(|| format!("{out:?} has no …"));
    };
    let from = s.len() - end.len();
    if !s.ends_with(end) || !s.is_char_boundary(from) {
        return Some(format!("{end:?} is not a char-aligned end"));
    }
    let prev = s[..from].chars().next_back().map(|c| format!("…{c}{end}"));
    let longer = prev.filter(|p| width(p, px) <= max_w);
    longer.map(|p| format!("{out:?} stops short of {p:?}"))
}

#[test]
fn tail_keeps_the_end_and_fits() {
    let _g = serial();
    let mut fails = Vec::new();
    for px in sizes() {
        for s in RUNS {
            for max_w in 0..=width(s, px) + 4 {
                let out = tail(s, max_w, px);
                let why = fault(s, max_w, px, &out);
                fails.extend(why.map(|w| format!("{s:?} at {px} in {max_w}: {w}")));
            }
        }
    }
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn tail_by_keeps_the_longest_end_that_fits() {
    assert_eq!(tail_by("abcdef", 60, tens), "abcdef");
    assert_eq!(tail_by("abcdef", 59, tens), "…cdef");
    assert_eq!(tail_by("日本語です", 35, tens), "…です");
    assert_eq!(tail_by("ü", 9, tens), "");
    assert_eq!(tail_by("üü", 10, tens), "…");
}
