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

//! Separator: the hairline, plain or soft, stays in its box at every scale.
//! Borders carry no contrast floor in colours.md, so none is checked.

use nonos_toolkit::widgets::Separator;

use super::bounds::{assert_bounded, assert_bounded_in};
use super::boxes::{boxed, FREE_W};
use super::serial::serial;

fn variants() -> Vec<(String, Separator)> {
    vec![("plain".to_string(), Separator::new()), ("soft".to_string(), Separator::new().soft())]
}

#[test]
fn separator_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
    assert_bounded_in(&variants(), |(_, h)| [boxed(1, h), boxed(FREE_W, h + 7), boxed(FREE_W, 0)]);
}
