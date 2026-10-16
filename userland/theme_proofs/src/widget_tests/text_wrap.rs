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

//! `wrap`: char-aligned ranges that cover the words in order, each line
//! within the width unless it is one word too wide for any line.

use nonos_toolkit::widgets::text::{width, wrap, wrap_by};

use super::samples::{sizes, tens, RUNS};
use super::serial::serial;

/// What is wrong with `lines` as `wrap(s, max_w, px)`, if anything.
fn fault(s: &str, max_w: u32, px: f32, lines: &[(usize, usize)]) -> Option<String> {
    let mut seen = 0;
    for &(a, b) in lines {
        if a < seen || a >= b || !s.is_char_boundary(a) || !s.is_char_boundary(b) {
            return Some(format!("({a}, {b}) is out of order or off a char boundary"));
        }
        if !s[seen..a].chars().all(char::is_whitespace) {
            return Some(format!("{:?} is skipped", &s[seen..a]));
        }
        let line = &s[a..b];
        let one_word = !line.contains(char::is_whitespace);
        if width(line, px) > max_w && !one_word {
            return Some(format!("{line:?} is {} wide, over {max_w}", width(line, px)));
        }
        seen = b;
    }
    let rest = &s[seen..];
    (!rest.chars().all(char::is_whitespace)).then(|| format!("{rest:?} is dropped"))
}

#[test]
fn wrap_covers_the_text_in_lines_that_fit() {
    let _g = serial();
    let mut fails = Vec::new();
    for px in sizes() {
        for s in RUNS {
            for max_w in (0..=width(s, px) + 8).step_by(3) {
                let why = fault(s, max_w, px, &wrap(s, max_w, px));
                fails.extend(why.map(|w| format!("{s:?} at {px} in {max_w}: {w}")));
            }
        }
    }
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn wrap_by_breaks_at_whitespace_and_keeps_long_words_whole() {
    let s = "ab cd  éf\tghijkl m";
    assert_eq!(wrap_by(s, 50, tens), vec![(0, 5), (7, 10), (11, 17), (18, 19)]);
    assert_eq!(wrap_by(s, 1000, tens), vec![(0, s.len())]);
    assert_eq!(wrap_by("   ", 50, tens), vec![]);
    assert_eq!(wrap_by("Grüße — 日本語", 30, tens), vec![(0, 7), (8, 11), (12, 21)]);
}
