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

//! The readability proof: a widget's ink against the ground right under it,
//! both read back from the pixels it drew.

use nonos_toolkit::theme::roles;

use super::read::reach;
use super::serial::per_theme;
use super::states::looks;
use super::widget::Widget;
use nonos_toolkit::widgets::State;

pub(crate) use super::read::{Off, Read, NONE};

/// The four grounds colours.md holds inks to, by name, in the theme in force.
fn grounds() -> [(&'static str, u32); 4] {
    let r = roles();
    let (bg, surface, sunken, raised) = (r.bg, r.surface, r.sunken, r.raised);
    [
        ("bg", bg.argb()),
        ("surface", surface.argb()),
        ("sunken", sunken.argb()),
        ("raised", raised.argb()),
    ]
}

/// Reads every ink in every theme, reading scale, look and ground, and asserts
/// each clears its floor.
pub(crate) fn assert_legible<W: Widget>(reads: &[Read<W>]) {
    assert_legible_in(reads, looks);
}

/// `assert_legible` over the states `states` gives.
pub(crate) fn assert_legible_in<W: Widget, S: Iterator<Item = State>>(
    reads: &[Read<W>],
    states: impl Fn() -> S,
) {
    let mut fails = Vec::new();
    per_theme(|theme| {
        for (ground, fill) in grounds() {
            for read in reads {
                for st in states() {
                    if st.disabled && read.floor <= NONE {
                        continue;
                    }
                    let r = reach(read, st, fill);
                    let free = st.disabled || read.floor <= NONE;
                    let ok = if free { r > NONE } else { r >= read.floor };
                    if !ok {
                        let what = read.what;
                        fails.push(format!("{theme} on {ground}: {what} {st:?} {r:.2}:1"));
                    }
                }
            }
        }
    });
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
