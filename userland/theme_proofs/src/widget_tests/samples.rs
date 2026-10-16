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

//! The runs the text helper proofs measure, multi-byte ones among them, and
//! the sizes they measure them at.

use nonos_toolkit::design::scale::scale;
use nonos_toolkit::design::text_role::TextRole;

/// Runs of one-, two-, three- and four-byte characters, spaced and unspaced.
pub(crate) const RUNS: [&str; 6] = [
    "Network settings",
    "Grüße — 日本語",
    "Grüße — 日本語 und noch mehr Wörter, die umbrechen müssen",
    "ééééééééééééé",
    "naïve café résumé",
    "a🙂b🙂c 🙂🙂🙂 end",
];

/// A run too long for any box a widget is given here.
pub(crate) const LONG: &str = "Grüße — 日本語 und noch mehr Wörter, die nicht passen";

/// The body, title and headline sizes at the scale in force.
pub(crate) fn sizes() -> [f32; 3] {
    let s = scale();
    [TextRole::Body, TextRole::Title, TextRole::Headline].map(|r| s.font(r.px()))
}

/// A measure that gives every char ten units, for checks that need exact
/// widths.
pub(crate) fn tens(s: &str) -> i32 {
    s.chars().count() as i32 * 10
}
