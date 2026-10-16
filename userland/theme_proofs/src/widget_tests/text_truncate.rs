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

//! `truncate`: the run unchanged when it fits; otherwise the longest prefix
//! cut on a char boundary that fits with `…`, or nothing.

use nonos_toolkit::widgets::text::{truncate, truncate_by, width};

use super::samples::{sizes, tens, RUNS};
use super::serial::serial;

/// What is wrong with `out` as `truncate(s, max_w, px)`, if anything.
fn fault(s: &str, max_w: u32, px: f32, out: &str) -> Option<String> {
    let w = width(out, px);
    if w > max_w {
        return Some(format!("{out:?} is {w} wide, over {max_w}"));
    }
    if width(s, px) <= max_w {
        return (out != s).then(|| format!("{out:?} changed a run that fits"));
    }
    let Some(stem) = out.strip_suffix('…') else {
        return (!out.is_empty() || width("…", px) <= max_w).then(|| format!("{out:?} has no …"));
    };
    if !s.starts_with(stem) || !s.is_char_boundary(stem.len()) {
        return Some(format!("{stem:?} is not a char-aligned prefix"));
    }
    let next = s[stem.len()..].chars().next().map(|c| format!("{stem}{c}…"));
    let longer = next.filter(|n| width(n, px) <= max_w);
    longer.map(|n| format!("{out:?} stops short of {n:?}"))
}

#[test]
fn truncate_fits_and_cuts_on_a_char_boundary() {
    let _g = serial();
    let mut fails = Vec::new();
    for px in sizes() {
        for s in RUNS {
            for max_w in 0..=width(s, px) + 4 {
                let out = truncate(s, max_w, px);
                let why = fault(s, max_w, px, &out);
                fails.extend(why.map(|w| format!("{s:?} at {px} in {max_w}: {w}")));
            }
        }
    }
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn truncate_by_keeps_the_longest_prefix_that_fits() {
    assert_eq!(truncate_by("abcdef", 60, tens), "abcdef");
    assert_eq!(truncate_by("abcdef", 59, tens), "abcd…");
    assert_eq!(truncate_by("日本語です", 35, tens), "日本…");
    assert_eq!(truncate_by("ü", 9, tens), "");
    assert_eq!(truncate_by("üü", 10, tens), "…");
}
