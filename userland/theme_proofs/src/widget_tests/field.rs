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

//! Field: text, placeholder, icon and caret stay in the box, a long text's
//! tail included, and the hit test takes the body it draws.

use nonos_toolkit::icons::IconId;
use nonos_toolkit::widgets::Field;

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::samples::LONG;
use super::serial::serial;

fn variants() -> Vec<(String, Field<'static>)> {
    let named = |n: &str, f| (n.to_string(), f);
    let search = Field::new("").placeholder("Search settings").icon(IconId::SettingsSearch);
    vec![
        named("text", Field::new("Grüße — 日本語")),
        named("placeholder", Field::new("").placeholder("Search settings")),
        named("icon and placeholder", search),
        named("icon and text", Field::new("wifi").icon(IconId::SettingsWifi)),
        named("caret at the end", Field::new("Grüße").caret(Some(7))),
        named("caret inside a char", Field::new("Grüße").caret(Some(3))),
        named("caret past the end", Field::new("Grüße").caret(Some(99))),
        named("caret in an empty field", Field::new("").placeholder("Name").caret(Some(0))),
        named("long with caret", Field::new(LONG).caret(Some(LONG.len()))),
        named("long caret at the start", Field::new(LONG).caret(Some(0))),
        named("long with icon", Field::new(LONG).icon(IconId::Files).caret(Some(5))),
        named("long placeholder", Field::new("").placeholder(LONG).icon(IconId::Files)),
    ]
}

#[test]
fn field_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn field_hit_takes_the_body_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |f, at, x, y| f.hit(at, x, y));
}
