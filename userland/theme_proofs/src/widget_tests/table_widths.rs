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

//! Table: the columns tile the width with no gap and no overlap, so their
//! widths add up to `at.w`, read back as the run of points each header
//! hit names. Fixed columns keep their width while it fits and shrink in
//! proportion when it does not; the shared ones split the rest by share.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::Table;

use super::boxes::boxed;
use super::serial::{serial, SCALES};
use super::table_spans::{cols, px, spans, MIXES, W};

/// What is wrong with `got`, the widths of `mix` across `w`, if anything.
fn wrong(mix: &[W], w: u32, got: &[u32]) -> Option<String> {
    let n = |c: &W| if let W::S(n) = c { *n } else { 0 };
    let (fixed, shares) = (mix.iter().map(px).sum::<u32>(), mix.iter().map(n).sum::<u32>());
    let room = w.saturating_sub(fixed) as f64;
    let lone = |i: usize| shares == 0 && i + 1 == mix.len();
    let want = |i: usize, c: &W| match c {
        _ if lone(i) && w >= fixed => (px(c) + w - fixed) as f64,
        W::F(_) if w >= fixed => px(c) as f64,
        W::F(_) => px(c) as f64 * w as f64 / fixed as f64,
        W::S(k) => room * *k as f64 / shares.max(1) as f64,
    };
    let bad = mix.iter().enumerate().find(|(i, c)| (got[*i] as f64 - want(*i, c)).abs() > 1.0);
    let sum = got.iter().sum::<u32>();
    (sum != w || bad.is_some()).then(|| format!("{got:?} sum {sum}, first off {bad:?}"))
}

#[test]
fn table_columns_add_up_to_the_width() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (m, mix) in MIXES.into_iter().enumerate() {
            let cols = cols(mix);
            let f = mix.iter().map(px).sum::<u32>();
            let t = Table::new(&cols);
            for w in (0..=600).step_by(7).chain([f.saturating_sub(1), f, f + 1, 1000]) {
                let at = boxed(w, t.size().1);
                let got = spans(t, at, mix.len());
                let line = got.map_or_else(Some, |got| wrong(mix, w, &got));
                fails.extend(line.map(|l| format!("mix {m} w {w} at {q}/4: {l}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
